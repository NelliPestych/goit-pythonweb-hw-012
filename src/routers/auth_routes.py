"""
Модуль для управління аутентифікацією та авторизацією користувачів.

Включає ендпоінти для реєстрації, входу, підтвердження електронної пошти
та отримання інформації про поточного користувача.
"""

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import timedelta, datetime
import json
import redis.asyncio as redis
import os

from src import schemas, crud, deps, models
from src.auth import (
    create_email_verification_token, decode_email_verification_token,
    verify_password, create_access_token, get_current_user,
    get_password_hash, create_password_reset_token, decode_password_reset_token,
    get_redis_client, USER_CACHE_EXPIRE_MINUTES,
    ACCESS_TOKEN_EXPIRE_MINUTES
)
from src.email_utils import send_email

router = APIRouter(prefix="/auth", tags=["Auth"])


@router.post("/signup", response_model=schemas.UserOut, status_code=status.HTTP_201_CREATED)
async def signup(body: schemas.UserCreate, background_tasks: BackgroundTasks, request: Request,
                 db: Session = Depends(deps.get_db)):
    """
    Реєструє нового користувача.

    Args:
        body (schemas.UserCreate): Дані для створення користувача (email, password).
        background_tasks (BackgroundTasks): Завдання для фонового виконання (відправка email).
        request (Request): Об'єкт запиту для формування посилання підтвердження.
        db (Session): Сесія бази даних.

    Raises:
        HTTPException:
            - 409 CONFLICT: Якщо користувач з таким email вже існує.
            - 500 INTERNAL_SERVER_ERROR: Якщо не вдалося створити користувача.

    Returns:
        schemas.UserOut: Створений об'єкт користувача (без хешованого пароля).
    """
    user = crud.get_user_by_email(db, body.email)
    if user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Account already exists")

    new_user = crud.create_user(db, body)
    if new_user is None:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not create user")

    token_verification = create_email_verification_token({"sub": new_user.email})

    base_url = str(request.url).replace(request.url.path, "")

    # Only send confirmation email if not in testing
    if os.getenv("TESTING") == "false":
        background_tasks.add_task(
            send_email,
            new_user.email,
            new_user.email,
            base_url,
            token_verification,
            subject="Confirm your email for Contacts App"
        )
    else:
        print("✅ MOCK EMAIL: confirmation email would be sent.")
    return new_user


@router.get("/confirm_email/{token}")
async def confirm_email(token: str, db: Session = Depends(deps.get_db)):
    """
    Підтверджує електронну пошту користувача за допомогою токена верифікації.

    Args:
        token (str): Токен верифікації, отриманий з посилання в електронному листі.
        db (Session): Сесія бази даних.

    Raises:
        HTTPException:
            - 400 BAD_REQUEST: Якщо токен недійсний або термін його дії минув.
            - 404 NOT_FOUND: Якщо користувача з таким email не знайдено.

    Returns:
        dict: Повідомлення про успішне підтвердження електронної пошти або про вже підтверджену пошту.
    """
    email = decode_email_verification_token(token)
    user = crud.get_user_by_email(db, email)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if user.confirmed:
        return {"message": "Email already confirmed"}

    user.confirmed = True
    db.commit()
    db.refresh(user)
    return {"message": "Email successfully confirmed"}


@router.post("/login", response_model=schemas.Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(deps.get_db),
                r: redis.Redis = Depends(get_redis_client)):
    """
    Аутентифікує користувача та повертає JWT токен доступу.

    Args:
        form_data (OAuth2PasswordRequestForm): Дані форми для входу (username - email, password).
        db (Session): Сесія бази даних.
        r (redis.Redis): Клієнт Redis для кешування.

    Raises:
        HTTPException:
            - 401 UNAUTHORIZED: Якщо email або пароль некоректні, або email не підтверджений.

    Returns:
        schemas.Token: Об'єкт, що містить токен доступу та його тип.
    """
    user = crud.get_user_by_email(db, form_data.username)
    if user is None or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.confirmed:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email not confirmed",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_dict = {
        "id": user.id,
        "email": user.email,
        "confirmed": user.confirmed,
        "avatar_url": user.avatar_url,
        "role": str(user.role.value),
        "created_at": user.created_at.isoformat(),
        "updated_at": user.updated_at.isoformat()
    }
    await r.setex(f"user:{user.email}", USER_CACHE_EXPIRE_MINUTES * 60, json.dumps(user_dict))

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/current_user", response_model=schemas.UserOut)
async def read_users_me(current_user: models.User = Depends(get_current_user), db: Session = Depends(deps.get_db)):
    """
    Отримує інформацію про поточного аутентифікованого користувача.

    Args:
        current_user (models.User): Об'єкт поточного користувача, отриманий через залежність.
        db (Session): Сесія бази даних.

    Returns:
        schemas.UserOut: Об'єкт користувача з публічними даними.
    """
    return current_user


@router.post("/request_reset_password", status_code=status.HTTP_200_OK)
async def request_reset_password(
        body: schemas.RequestEmail,
        background_tasks: BackgroundTasks,
        request: Request,
        db: Session = Depends(deps.get_db)
):
    """
    Запитує скидання пароля для користувача.

    Генерує токен скидання пароля та надсилає його на електронну пошту користувача.

    Args:
        body (schemas.RequestEmail): Об'єкт, що містить email користувача.
        background_tasks (BackgroundTasks): Завдання для фонової відправки email.
        request (Request): Об'єкт запиту для формування посилання.
        db (Session): Сесія бази даних.

    Raises:
        HTTPException:
            - 404 NOT_FOUND: Якщо користувача з таким email не знайдено.
            - 403 FORBIDDEN: Якщо email не підтверджений (щоб уникнути спаму).

    Returns:
        dict: Повідомлення про успішне відправлення листа.
    """
    user = crud.get_user_by_email(db, body.email)

    if not user:
        raise HTTPException(status_code=404, detail="Not Found")

    if not user.confirmed:
        raise HTTPException(status_code=403, detail="Email not confirmed. Please confirm your email first.")

    token_reset = create_password_reset_token({"sub": user.email})

    base_url = str(request.url).replace(request.url.path, "")

    if os.getenv("TESTING") == "false":
        background_tasks.add_task(
            send_email,
            user.email,
            user.email,
            base_url,
            token_reset,
            subject="Password Reset Request"
        )

    return {"message": "If a user with that email exists and is confirmed, a password reset link has been sent."}


@router.post("/reset_password/{token}", status_code=status.HTTP_200_OK)
async def reset_password(
        token: str,
        body: schemas.UserLogin,
        db: Session = Depends(deps.get_db),
        r: redis.Redis = Depends(get_redis_client)
):
    """
    Скидає пароль користувача за допомогою токена скидання пароля.

    Args:
        token (str): Токен скидання пароля.
        body (schemas.UserLogin): Об'єкт, що містить email та новий пароль.
        db (Session): Сесія бази даних.
        r (redis.Redis): Клієнт Redis для очищення кешу користувача.

    Raises:
        HTTPException:
            - 400 BAD_REQUEST: Якщо токен недійсний або термін його дії минув,
                               або email у токені не збігається з наданим.
            - 404 NOT_FOUND: Якщо користувача з таким email не знайдено.

    Returns:
        dict: Повідомлення про успішне скидання пароля.
    """
    email_from_token = decode_password_reset_token(token)

    if email_from_token != body.email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email in token does not match provided email.",
        )

    user = crud.get_user_by_email(db, body.email)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.hashed_password = get_password_hash(body.password)
    db.commit()
    db.refresh(user)

    await r.delete(f"user:{user.email}")

    return {"message": "Password has been successfully reset."}

@router.post("/request_email_confirmation", status_code=status.HTTP_200_OK)
async def request_email_confirmation(
        body: schemas.RequestEmail,
        background_tasks: BackgroundTasks,
        request: Request,
        db: Session = Depends(deps.get_db)
):
    """
    Повторно надсилає лист для підтвердження електронної пошти.

    Args:
        body (schemas.RequestEmail): Об'єкт, що містить email користувача.
        background_tasks (BackgroundTasks): Завдання для фонової відправки email.
        request (Request): Об'єкт запиту для формування посилання.
        db (Session): Сесія бази даних.

    Raises:
        HTTPException:
            - 404 NOT_FOUND: Якщо користувача з таким email не знайдено.
            - 409 CONFLICT: Якщо email вже підтверджений.

    Returns:
        dict: Повідомлення про успішне відправлення листа підтвердження.
    """
    user = crud.get_user_by_email(db, body.email)
    if user is None:
        raise HTTPException(status_code=404, detail="Not Found")

    if user.confirmed:
        raise HTTPException(status_code=409, detail="Your email is already confirmed.")

    token_verification = create_email_verification_token({"sub": user.email})
    base_url = str(request.url).replace(request.url.path, "")

    if os.getenv("TESTING") == "false":
        background_tasks.add_task(
            send_email,
            user.email,
            user.email,
            base_url,
            token_verification,
            subject="Confirm your email for Contacts App"
        )
    else:
        print("✅ MOCK EMAIL: confirmation email would be sent.")
    return {"message": "Confirmation email sent."}

