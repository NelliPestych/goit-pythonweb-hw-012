# app/auth.py
"""
Модуль для управління аутентифікацією та авторизацією користувачів,
включаючи кешування даних користувачів за допомогою Redis.
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
import redis.asyncio as redis # Імпортуємо redis.asyncio

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
EMAIL_VERIFICATION_TOKEN_EXPIRE_MINUTES = int(os.getenv("EMAIL_VERIFICATION_TOKEN_EXPIRE_MINUTES", 60 * 24)) # 24 години
# Додаємо час життя кешу для користувача
USER_CACHE_EXPIRE_MINUTES = int(os.getenv("USER_CACHE_EXPIRE_MINUTES", 60)) # Кешуємо користувача на 1 годину

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

# Ініціалізуємо Redis клієнт. Важливо: він буде використовуватися в async функціях
# Його потрібно буде ініціалізувати в startup події, як це зроблено для FastAPILimiter
# Або ж можна передавати його як залежність, як ми зробимо тут для простоти
# Для цього потрібно буде створити функцію get_redis_client в deps.py
# Або використовувати глобальний об'єкт (як для FastAPILimiter), але це може бути складніше.
# Для початку, давайте створимо тимчасовий Redis клієнт тут, але потім це треба буде покращити.

# Важливо: Цей Redis клієнт тут - це тимчасове рішення для швидкого прототипування.
# У production додатку, Redis клієнт має бути ініціалізований один раз на старті програми
# (наприклад, у main.py в startup події) і передаватися через залежності.
# Для цієї демонстрації ми будемо створювати його "на льоту".

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
    # Додаємо залежність для Redis клієнта
    # У production додатках, це має бути singleton або connection pool
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

    # Ключ для кешування користувача. Використовуємо email як унікальний ідентифікатор.
    # Можна використовувати user.id після першого отримання з БД.
    cache_key = f"user:{email}"

    # Спроба отримати користувача з кешу Redis
    cached_user_data = await r.get(cache_key) # [cite: get_redis_client]
    if cached_user_data:
        # Якщо дані є в кеші, десеріалізуємо їх і повертаємо об'єкт User
        user_data = json.loads(cached_user_data)
        # SQLAlchemy об'єкти не можна просто серіалізувати в JSON.
        # Тому потрібно створити об'єкт моделі з JSON даних.
        # Переконайтеся, що `models.User` має конструктор, який приймає ключові аргументи,
        # або створіть функцію для мапування.
        # Припускаємо, що models.User(**user_data) працюватиме для простих полів.
        # Приведення UserRole з рядка назад до Enum
        if 'role' in user_data and isinstance(user_data['role'], str):
            from app.models import UserRole # Імпортуємо UserRole
            user_data['role'] = UserRole(user_data['role'])
        user = models.User(**user_data)
        print(f"User {email} loaded from Redis cache.")
        return user

    # Якщо користувача немає в кеші, отримуємо його з бази даних
    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Серіалізуємо об'єкт користувача в JSON і зберігаємо в кеші
    # Важливо: SQLAlchemy моделі не можуть бути напряму серіалізовані в JSON.
    # Потрібно перетворити об'єкт User на словник.
    # Використовуємо __dict__ або Pydantic схему, якщо є.
    # Для простоти, створюємо словник з необхідних полів.
    user_dict = {
        "id": user.id,
        "email": user.email,
        "confirmed": user.confirmed,
        "avatar_url": user.avatar_url,
        # Додайте інші поля, які ви хочете кешувати
        # 'hashed_password' не слід кешувати відкрито
        "role": str(user.role.value) # <--- ВИПРАВЛЕНО: Конвертуємо Enum до рядка для JSON
    }
    await r.setex(cache_key, USER_CACHE_EXPIRE_MINUTES * 60, json.dumps(user_dict)) # [cite: get_redis_client]
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
