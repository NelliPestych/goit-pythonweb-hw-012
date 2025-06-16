# app/auth.py
"""
Модуль для управління аутентифікацією та авторизацією користувачів,
включаючи кешування даних користувачів за допомогою Redis.
Цей файл містить основні функції, що не є маршрутами FastAPI.
"""

from datetime import datetime, timedelta, timezone # ДОДАНО timezone
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

    Ця функція є залежністю FastAPI і повертає інстанс Redis клієнта.
    """
    redis_host = os.getenv("REDIS_HOST", "localhost")
    redis_port = int(os.getenv("REDIS_PORT", 6379))
    return redis.Redis(host=redis_host, port=redis_port, db=0, encoding="utf-8", decode_responses=True)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Перевіряє відповідність пароля хешу."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Генерує хеш пароля."""
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Створює JWT токен доступу."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta # Use timezone.utc for consistency
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)}) # Add issued at
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_email_verification_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Створює JWT токен для підтвердження електронної пошти."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=EMAIL_VERIFICATION_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_email_verification_token(token: str) -> str:
    """Декодує JWT токен підтвердження електронної пошти."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token payload")
        return email
    except JWTError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Could not validate credentials or token expired")

def create_password_reset_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
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
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=PASSWORD_RESET_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_password_reset_token(token: str) -> str:
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
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token payload")
        return email
    except JWTError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Could not validate credentials or token expired")


async def get_current_user(token: str = Depends(oauth2_scheme),
                           db: Session = Depends(deps.get_db),
                           r: redis.Redis = Depends(get_redis_client)) -> models.User:
    """
    Залежність FastAPI, що повертає поточного аутентифікованого користувача.

    Args:
        token (str): JWT токен з заголовка авторизації.
        db (Session): Сесія бази даних.
        r (redis.Redis): Клієнт Redis для кешування.

    Raises:
        HTTPException:
            - 401 UNAUTHORIZED: Якщо токен недійсний, термін дії минув,
                                або користувача не знайдено/не підтверджено.

    Returns:
        models.User: Об'єкт поточного користувача.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user_key = f"user:{email}"
    # Намагаємося отримати користувача з кешу Redis
    cached_user_data = await r.get(user_key)
    if cached_user_data:
        # print(f"DEBUG: User {email} found in Redis cache.") # Дебаг
        user_dict = json.loads(cached_user_data)
        # Перетворюємо назад в об'єкт моделі User
        user = models.User(**user_dict)
        # Приведення datetime та enum з JSON
        if user_dict.get('created_at'):
            user.created_at = datetime.fromisoformat(user_dict['created_at'])
        if user_dict.get('updated_at'):
            user.updated_at = datetime.fromisoformat(user_dict['updated_at'])
        user.role = models.UserRole(user_dict['role']) # Конвертуємо назад в Enum
        return user

    # Якщо користувача немає в кеші, отримуємо його з бази даних
    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        raise credentials_exception
    if not user.confirmed:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Email not confirmed")

    # Зберігаємо користувача в кеші Redis
    # Перетворюємо об'єкт User на словник, включаючи enum UserRole
    user_dict = {c.name: getattr(user, c.name) for c in user.__table__.columns}
    user_dict['role'] = user.role.value if user.role else None # Серіалізуємо Enum
    user_dict['created_at'] = user_dict['created_at'].isoformat() if user_dict['created_at'] else None
    user_dict['updated_at'] = user_dict['updated_at'].isoformat() if user_dict['updated_at'] else None

    # Додаємо аватару, якщо вона є
    if hasattr(user, 'avatar_url'):
        user_dict['avatar_url'] = user.avatar_url


    await r.setex(user_key, timedelta(minutes=USER_CACHE_EXPIRE_MINUTES), json.dumps(user_dict))
    # print(f"DEBUG: User {email} cached in Redis.") # Дебаг
    return user

async def get_current_admin_user(current_user: models.User = Depends(get_current_user)):
    """
    Залежність, що повертає поточного адміністратора.

    Використовується для маршрутів, доступних лише адміністраторам.

    Raises:
        HTTPException: 403 FORBIDDEN, якщо користувач не є адміністратором.

    Returns:
        models.User: Об'єкт поточного адміністратора.
    """
    if current_user.role != models.UserRole.admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")
    return current_user