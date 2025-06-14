# app/auth.py
"""
Модуль для управління аутентифікацією та авторизацією користувачів,
включаючи кешування даних користувачів за допомогою Redis та механізм скидання пароля.
"""

from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status, BackgroundTasks, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from dotenv import load_dotenv
import os
from sqlalchemy.orm import Session
from app import models, deps, schemas, crud
import json
import redis.asyncio as redis
from app.email import send_email  # Переконайтеся, що app.email існує і send_email реалізовано

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
EMAIL_VERIFICATION_TOKEN_EXPIRE_MINUTES = int(
    os.getenv("EMAIL_VERIFICATION_TOKEN_EXPIRE_MINUTES", 60 * 24))  # 24 години
PASSWORD_RESET_TOKEN_EXPIRE_MINUTES = int(
    os.getenv("PASSWORD_RESET_TOKEN_EXPIRE_MINUTES", 60))  # 1 година для токена скидання пароля
USER_CACHE_EXPIRE_MINUTES = int(os.getenv("USER_CACHE_EXPIRE_MINUTES", 60))  # Кешуємо користувача на 1 годину

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")


async def get_redis_client() -> redis.Redis:
    """
    Отримує асинхронний клієнт Redis.

    Ця функція є тимчасовою для демонстрації кешування. У production додатку
    клієнт Redis слід ініціалізувати один раз при запуску програми
    і передавати як залежність або через глобальний об'єкт.

    Returns:
        redis.Redis: Асинхронний клієнт Redis.
    """
    redis_host = os.getenv("REDIS_HOST", "localhost")
    redis_port = int(os.getenv("REDIS_PORT", 6379))
    return redis.Redis(host=redis_host, port=redis_port, db=0, encoding="utf-8", decode_responses=True)


def verify_password(plain_password, hashed_password):
    """
    Перевіряє, чи відповідає наданий пароль хешованому паролю.

    Args:
        plain_password (str): Пароль у відкритому вигляді.
        hashed_password (str): Хешований пароль.

    Returns:
        bool: True, якщо паролі збігаються, інакше False.
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    """
    Хешує наданий пароль.

    Args:
        password (str): Пароль у відкритому вигляді.

    Returns:
        str: Хешований пароль.
    """
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """
    Створює JWT токен доступу.

    Args:
        data (dict): Дані, які потрібно закодувати в токен (наприклад, {"sub": "user_email"}).
        expires_delta (Optional[timedelta]): Термін дії токена. Якщо None, використовується
                                             значення за замовчуванням `ACCESS_TOKEN_EXPIRE_MINUTES`.

    Returns:
        str: Закодований JWT токен.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_token(token: str):
    """
    Декодує JWT токен.

    Args:
        token (str): JWT токен.

    Raises:
        HTTPException:
            - 401 UNAUTHORIZED: Якщо токен недійсний або його не вдалося декодувати.

    Returns:
        dict: Декодоване навантаження (payload) токена.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(
        token: str = Depends(oauth2_scheme),
        db: Session = Depends(deps.get_db),
        r: redis.Redis = Depends(get_redis_client)
) -> models.User:
    """
    Отримує поточного аутентифікованого користувача.

    Спочатку намагається отримати дані користувача з кешу Redis.
    Якщо користувача немає в кеші, звертається до бази даних і кешує результат.

    Args:
        token (str): JWT токен з заголовка Authorization.
        db (Session): Сесія бази даних.
        r (redis.Redis): Клієнт Redis для кешування.

    Raises:
        HTTPException:
            - 401 UNAUTHORIZED: Якщо не вдалося перевірити облікові дані.

    Returns:
        models.User: Об'єкт поточного користувача.
    """
    payload = decode_token(token)
    email: str = payload.get("sub")
    if email is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    cache_key = f"user:{email}"

    cached_user_data = await r.get(cache_key)
    if cached_user_data:
        user_data = json.loads(cached_user_data)
        user = models.User(**user_data)
        print(f"User {email} loaded from Redis cache.")
        return user

    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_dict = {
        "id": user.id,
        "email": user.email,
        "confirmed": user.confirmed,
        "avatar_url": user.avatar_url,
        # Додаємо роль до кешованих даних
        "role": user.role  # Припускаємо, що у моделі User є поле 'role'
    }
    await r.setex(cache_key, USER_CACHE_EXPIRE_MINUTES * 60, json.dumps(user_dict))
    print(f"User {email} loaded from DB and cached in Redis.")

    return user


def create_email_verification_token(data: dict, expires_delta: Optional[timedelta] = None):
    """
    Створює JWT токен для верифікації електронної пошти.

    Args:
        data (dict): Дані, які потрібно закодувати в токен (наприклад, {"sub": "user_email"}).
        expires_delta (Optional[timedelta]): Термін дії токена. Якщо None, використовується
                                             значення за замовчуванням `EMAIL_VERIFICATION_TOKEN_EXPIRE_MINUTES`.

    Returns:
        str: Закодований JWT токен.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=EMAIL_VERIFICATION_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_email_verification_token(token: str):
    """
    Декодує JWT токен верифікації електронної пошти.

    Args:
        token (str): Токен верифікації.

    Raises:
        HTTPException:
            - 400 BAD_REQUEST: Якщо токен недійсний або термін його дії минув.

    Returns:
        str: Електронна пошта користувача з токена.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token")
        return email
    except JWTError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired verification token")


def create_password_reset_token(data: dict, expires_delta: Optional[timedelta] = None):
    """
    Створює JWT токен для скидання пароля.

    Args:
        data (dict): Дані, які потрібно закодувати в токен (наприклад, {"sub": "user_email"}).
        expires_delta (Optional[timedelta]): Термін дії токена. Якщо None, використовується
                                             значення за замовчуванням `PASSWORD_RESET_TOKEN_EXPIRE_MINUTES`.

    Returns:
        str: Закодований JWT токен.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=PASSWORD_RESET_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_password_reset_token(token: str):
    """
    Декодує JWT токен скидання пароля.

    Args:
        token (str): Токен скидання пароля.

    Raises:
        HTTPException:
            - 400 BAD_REQUEST: Якщо токен недійсний або термін його дії минув.

    Returns:
        str: Електронна пошта користувача з токена.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid reset token")
        return email
    except JWTError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired password reset token")


# --- Ендпоінти аутентифікації ---
# (Залишаємо існуючі та додаємо нові)

from app.routers.auth import router  # Імпортуємо router з app.routers.auth


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

    Returns:
        schemas.UserOut: Створений об'єкт користувача (без хешованого пароля).
    """
    user = crud.get_user_by_email(db, body.email)
    if user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Account already exists")

    new_user = crud.create_user(db, body)
    if new_user is None:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not create user")

    # Створення та відправка токена для підтвердження email
    token_verification = create_email_verification_token({"sub": new_user.email})

    # Виправлений виклик send_email із вказанням усіх необхідних аргументів
    background_tasks.add_task(
        send_email,
        email=new_user.email,
        username=new_user.email,
        host=str(request.base_url),
        token=token_verification
    )

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
        dict: Повідомлення про успішне підтвердження електронної пошти.
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

    # При успішному вході, оновлюємо кеш користувача
    user_dict = {
        "id": user.id,
        "email": user.email,
        "confirmed": user.confirmed,
        "avatar_url": user.avatar_url,
        "role": user.role
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

    Raises:
        HTTPException:
            - 404 NOT_FOUND: Якщо користувача не знайдено в базі даних (хоча це малоймовірно,
                             якщо `get_current_user` успішно повернув об'єкт).

    Returns:
        schemas.UserOut: Об'єкт користувача з публічними даними.
    """
    # current_user вже був отриманий через get_current_user, який кешує дані.
    # Тут ми можемо просто повернути його.
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
            - 400 BAD_REQUEST: Якщо email не підтверджений (щоб уникнути спаму).

    Returns:
        dict: Повідомлення про успішне відправлення листа.
    """
    user = crud.get_user_by_email(db, body.email)
    if user is None:
        # Для безпеки не повідомляємо, чи існує користувач.
        # Просто повертаємо успішне повідомлення, щоб уникнути перебору email.
        return {"message": "If a user with that email exists, a password reset link has been sent."}

    if not user.confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email not confirmed. Please confirm your email first.",
        )

    token_reset = create_password_reset_token({"sub": user.email})

    # Формування посилання для скидання пароля
    base_url = str(request.url).replace(request.url.path, "")
    reset_link = f"{base_url}/api/auth/reset_password/{token_reset}"

    background_tasks.add_task(send_email, user.email, user.email, reset_link, subject="Password Reset Request")
    return {"message": "If a user with that email exists and is confirmed, a password reset link has been sent."}


@router.post("/reset_password/{token}", status_code=status.HTTP_200_OK)
async def reset_password(
        token: str,
        body: schemas.UserLogin,  # Використовуємо UserLogin для отримання нового пароля
        db: Session = Depends(deps.get_db),
        r: redis.Redis = Depends(get_redis_client)  # Додаємо Redis для очищення кешу
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

    # Хешуємо новий пароль
    user.hashed_password = get_password_hash(body.password)
    db.commit()
    db.refresh(user)

    # Очищаємо кеш користувача в Redis після зміни пароля
    await r.delete(f"user:{user.email}")

    return {"message": "Password has been successfully reset."}