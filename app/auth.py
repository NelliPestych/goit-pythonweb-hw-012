# app/auth.py
"""
Модуль для управління аутентифікацією та авторизацією користувачів,
включаючи кешування даних користувачів за допомогою Redis.
Цей файл містить основні функції, що не є маршрутами FastAPI.
"""

from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from dotenv import load_dotenv
import os
from sqlalchemy.orm import Session
from app import models, deps
import json
import redis.asyncio as redis

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
EMAIL_VERIFICATION_TOKEN_EXPIRE_MINUTES = int(os.getenv("EMAIL_VERIFICATION_TOKEN_EXPIRE_MINUTES", 60 * 24))
PASSWORD_RESET_TOKEN_EXPIRE_MINUTES = int(os.getenv("PASSWORD_RESET_TOKEN_EXPIRE_MINUTES", 60))
USER_CACHE_EXPIRE_MINUTES = int(os.getenv("USER_CACHE_EXPIRE_MINUTES", 60))

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
        if 'role' in user_data and isinstance(user_data['role'], str):
            from app.models import UserRole
            user_data['role'] = UserRole(user_data['role'])
        # Перетворення строкових дат з Redis назад в об'єкти datetime
        if 'created_at' in user_data and isinstance(user_data['created_at'], str):
            user_data['created_at'] = datetime.fromisoformat(user_data['created_at'])
        if 'updated_at' in user_data and isinstance(user_data['updated_at'], str):
            user_data['updated_at'] = datetime.fromisoformat(user_data['updated_at'])

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
        "role": str(user.role.value),
        "created_at": user.created_at.isoformat(), # Перетворення datetime в ISO рядок
        "updated_at": user.updated_at.isoformat()  # Перетворення datetime в ISO рядок
    }
    await r.setex(cache_key, USER_CACHE_EXPIRE_MINUTES * 60, json.dumps(user_dict))
    print(f"User {email} loaded from DB and cached in Redis.")

    return user

async def get_current_admin_user(current_user: models.User = Depends(get_current_user)) -> models.User:
    """
    Залежність FastAPI, яка перевіряє, чи поточний користувач є адміністратором.

    Args:
        current_user (models.User): Поточний автентифікований користувач.

    Raises:
        HTTPException:
            - 403 FORBIDDEN: Якщо користувач не має ролі "admin".

    Returns:
        models.User: Об'єкт користувача, якщо він є адміністратором.
    """
    if current_user.role != models.UserRole.admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation forbidden: Only administrators can perform this action."
        )
    return current_user

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
