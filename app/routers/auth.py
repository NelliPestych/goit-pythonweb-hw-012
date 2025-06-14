# app/routers/auth.py
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

from app import schemas, crud, deps, models
from app.auth import (
    create_email_verification_token, decode_email_verification_token,
    verify_password, create_access_token, get_current_user,
    get_password_hash, create_password_reset_token, decode_password_reset_token,
    get_redis_client, USER_CACHE_EXPIRE_MINUTES
)
from app.email import send_email

router = APIRouter(prefix="/auth", tags=["Auth"])


@router.post("/signup", response_model=schemas.UserOut, status_code=status.HTTP_201_CREATED)
async def signup(body: schemas.UserCreate, background_tasks: BackgroundTasks, request: Request,
                 db: Session = Depends(deps.get_db)):
    """
    Реєструє нового користувача.

    Args:
        body (schemas.UserCreate): Дані для реєстрації користувача.
        background_tasks (BackgroundTasks): Об'єкт для фонових задач.
        request (Request): Об'єкт запиту для формування URL.
        db (Session): Сесія бази даних.

    Raises:
        HTTPException: 409 CONFLICT, якщо користувач з таким email вже існує.

    Returns:
        schemas.UserOut: Створений користувач.
    """
    user = crud.get_user_by_email(db, body.email)
    if user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Account already exists")
    user = crud.create_user(db, body)

    # Генеруємо токен підтвердження email
    token_data = {"sub": user.email}
    token = create_email_verification_token(token_data)

    # Формуємо URL для підтвердження
    # Використовуємо request.url.scheme та request.client.host для динамічного формування базового URL
    # Якщо ви використовуєте проксі (наприклад, Nginx, Traefik), переконайтеся, що FastAPILimiter
    # правильно налаштований для отримання коректних заголовків X-Forwarded-For/Proto.
    # Для Docker Compose, зазвичай localhost:8000 працює.
    # Якщо додаток буде розгорнуто, вам слід використовувати доменне ім'я.
    confirm_url = str(request.url_for("confirm_email", token=token))

    # Додаємо завдання надсилання email у фоновий режим
    background_tasks.add_task(send_email, user.email, confirm_url, {"username": user.email})

    return user


@router.get("/confirm_email/{token}", response_model=schemas.Message)
async def confirm_email(token: str, db: Session = Depends(deps.get_db)):
    """
    Підтверджує електронну пошту користувача за допомогою токена.

    Args:
        token (str): Токен підтвердження електронної пошти.
        db (Session): Сесія бази даних.

    Raises:
        HTTPException: 400 BAD_REQUEST, якщо токен недійсний або термін його дії минув.

    Returns:
        schemas.Message: Повідомлення про успішне підтвердження.
    """
    email = decode_email_verification_token(token)
    if email is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired token")

    user = crud.get_user_by_email(db, email)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if user.confirmed:
        return {"message": "Email already confirmed."}  # Додаємо повідомлення, якщо email вже підтверджено

    crud.confirm_user_email(db, user)
    return {"message": "Email successfully confirmed!"}


@router.post("/login", response_model=schemas.Token)
async def login(body: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(deps.get_db),
                r: redis.Redis = Depends(get_redis_client)):
    """
    Аутентифікує користувача та повертає токен доступу.

    Args:
        body (OAuth2PasswordRequestForm): Об'єкт, що містить ім'я користувача (email) та пароль.
        db (Session): Сесія бази даних.
        r (redis.Redis): Клієнт Redis для кешування інформації про користувача.

    Raises:
        HTTPException: 401 UNAUTHORIZED, якщо облікові дані недійсні або email не підтверджений.

    Returns:
        schemas.Token: Токен доступу та тип токена.
    """
    user = crud.get_user_by_email(db, body.username)
    if user is None or not verify_password(body.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    if not user.confirmed:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Email not confirmed")

    # Створення токенів
    access_token_expires = timedelta(minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30)))
    access_token = create_access_token(
        data={"sub": user.email, "roles": user.role.value},  # Передаємо role як рядок
        expires_delta=access_token_expires
    )

    refresh_token_expires = timedelta(days=int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 7)))
    refresh_token = create_access_token(
        data={"sub": user.email, "roles": user.role.value, "type": "refresh"},  # Передаємо role як рядок
        expires_delta=refresh_token_expires
    )

    # Готуємо словник користувача для кешування в Redis
    # Перетворюємо об'єкт UserRole на його строкове значення (.value)
    user_dict = {
        "id": user.id,
        "email": user.email,
        "confirmed": user.confirmed,
        "role": user.role.value,  # !!! ВАЖЛИВА ЗМІНА ТУТ !!!
        "avatar_url": user.avatar_url
        # Не включайте hashed_password або інші чутливі дані
    }

    # Кешуємо інформацію про користувача в Redis
    await r.setex(f"user:{user.email}", USER_CACHE_EXPIRE_MINUTES * 60, json.dumps(user_dict))

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@router.get("/current_user", response_model=schemas.UserOut)
async def read_users_me(current_user: models.User = Depends(get_current_user)):
    """
    Отримує інформацію про поточного аутентифікованого користувача.

    Args:
        current_user (models.User): Поточний користувач, отриманий з токена.

    Returns:
        models.User: Об'єкт поточного користувача.
    """
    return current_user


@router.post("/request_reset_password", response_model=schemas.Message)
async def request_reset_password(body: schemas.PasswordResetRequest, background_tasks: BackgroundTasks,
                                 request: Request,
                                 db: Session = Depends(deps.get_db)):
    """
    Запитує скидання пароля, надсилаючи токен на електронну пошту користувача.

    Args:
        body (schemas.PasswordResetRequest): Об'єкт, що містить email користувача.
        background_tasks (BackgroundTasks): Об'єкт для фонових задач.
        request (Request): Об'єкт запиту для формування URL.
        db (Session): Сесія бази даних.

    Raises:
        HTTPException: 404 NOT_FOUND, якщо користувача з таким email не знайдено.

    Returns:
        schemas.Message: Повідомлення про успішне надсилання токена.
    """
    user = crud.get_user_by_email(db, body.email)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    token_data = {"sub": user.email}
    token = create_password_reset_token(token_data)

    reset_url = str(request.url_for("reset_password", token=token))
    background_tasks.add_task(send_email, user.email, reset_url, {"username": user.email}, subject="Password Reset")

    return {"message": "Password reset email sent."}


@router.post("/reset_password/{token}", response_model=schemas.Message)
async def reset_password(token: str, body: schemas.UserLogin,
                         db: Session = Depends(deps.get_db),
                         r: redis.Redis = Depends(get_redis_client)):  # Додаємо Redis для очищення кешу
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

    # Хешуємо новий пароль
    user.hashed_password = get_password_hash(body.password)
    crud.update_user(db, user)  # Оновлюємо користувача в БД

    # Очищаємо кеш користувача в Redis після скидання пароля
    # Це гарантує, що старий кешований запис (з можливим старим паролем) буде видалено
    await r.delete(f"user:{user.email}")

    return {"message": "Password has been reset successfully."}
