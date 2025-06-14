# app/schemas.py
"""
Модуль, що визначає схеми Pydantic для Contacts App API.

Ці схеми використовуються для валідації вхідних даних запитів
та серіалізації вихідних даних відповідей.
"""

from pydantic import BaseModel, EmailStr, Field
from datetime import date, datetime
from typing import Optional


# Загальна схема для повідомлень
class Message(BaseModel):
    """
    Схема для загальних повідомлень, що повертаються API.
    """
    message: str


# Схеми для користувачів
class UserCreate(BaseModel):
    """
    Схема для створення нового користувача.
    """
    email: EmailStr
    password: str = Field(min_length=6, max_length=255)


class UserOut(BaseModel):
    """
    Схема для представлення даних користувача у відповідях API.
    """
    id: int
    email: EmailStr
    confirmed: bool
    created_at: datetime
    updated_at: datetime
    avatar_url: Optional[str] = None
    role: str # Тепер очікуємо, що роль буде рядком

    class Config:
        from_attributes = True


class UserLogin(BaseModel):
    """
    Схема для входу користувача.
    """
    email: EmailStr
    password: str = Field(min_length=6, max_length=255)


class Token(BaseModel):
    """
    Схема для токенів доступу та оновлення.
    """
    access_token: str
    refresh_token: str
    token_type: str


class PasswordResetRequest(BaseModel):
    """
    Схема для запиту скидання пароля.
    (Це було додано раніше, але я залишаю її тут для повноти)
    """
    email: EmailStr


# !!! НОВА СХЕМА: RequestEmail !!!
class RequestEmail(BaseModel):
    """
    Схема для запитів, що потребують лише email.
    Використовується, наприклад, для повторного надсилання листа підтвердження.
    """
    email: EmailStr


# Схеми для контактів
class ContactBase(BaseModel):
    """
    Базова схема для контакту.
    """
    first_name: str = Field(max_length=50)
    last_name: str = Field(max_length=50)
    email: EmailStr
    phone: str = Field(max_length=20)
    birthday: date
    additional_info: Optional[str] = Field(None, max_length=255)


class ContactCreate(ContactBase):
    """
    Схема для створення нового контакту.
    """
    pass


class ContactUpdate(ContactBase):
    """
    Схема для оновлення існуючого контакту.
    """
    pass


class ContactOut(ContactBase):
    """
    Схема для представлення даних контакту у відповідях API.
    """
    id: int
    user_id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# Схема для оновлення URL аватара користувача
class AvatarUpdate(BaseModel):
    """
    Схема для оновлення URL аватара користувача.
    """
    avatar_url: str
