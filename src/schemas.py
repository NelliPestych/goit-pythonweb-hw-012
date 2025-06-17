"""
Модуль, що визначає схеми даних (Pydantic моделі)
для валідації вхідних та вихідних даних API.
"""

from pydantic import BaseModel, EmailStr, Field
from datetime import date, datetime
from typing import Optional
from src.models import UserRole

class ContactBase(BaseModel):
    """
    Базова схема для контакту, містить спільні поля для створення та оновлення.
    """
    first_name: str
    last_name: str
    email: EmailStr
    phone: str
    birthday: date
    additional_info: Optional[str] = None

class ContactCreate(ContactBase):
    """
    Схема для створення нового контакту. Успадковує поля з ContactBase.
    """
    pass

class ContactUpdate(BaseModel):
    """
    Схема для оновлення існуючого контакту. Всі поля є опціональними.
    """
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    birthday: Optional[date] = None
    additional_info: Optional[str] = None


class ContactOut(ContactBase):
    """
    Схема для виведення інформації про контакт.
    Включає ID та таймстемпи створення/оновлення.
    """
    id: int
    created_at: Optional[datetime]
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None,
            date: lambda v: v.isoformat() if v else None,
        }

class UserBase(BaseModel):
    """
    Базова схема для користувача, містить лише email.
    """
    email: EmailStr

class UserCreate(UserBase):
    """
    Схема для створення нового користувача.
    Включає email та пароль.
    """
    password: str = Field(min_length=6) # Валідація мінімальної довжини пароля

class UserLogin(UserBase):
    """
    Схема для входу користувача.
    Включає email та пароль.
    """
    password: str = Field(min_length=6) # Валідація мінімальної довжини пароля

class PasswordResetRequest(BaseModel):
    """
    Схема для запиту скидання пароля, що містить email та новий пароль.
    Ця схема, схоже, використовується не для ініціації скидання (там RequestEmail),
    а для безпосереднього оновлення пароля після переходу за посиланням з токеном.
    (Залишено як є з вашого файлу, хоча назва може бути дещо заплутана без контексту маршруту).
    """
    email: EmailStr
    password: str = Field(min_length=6) # Це буде новий пароль

class UserOut(UserBase):
    """
    Схема для виведення інформації про користувача.
    Включає ID, статус підтвердження, таймстемпи, роль та URL аватара.
    """
    id: int
    confirmed: bool
    created_at: Optional[datetime]
    updated_at: Optional[datetime]
    role: UserRole
    avatar_url: Optional[str] = None # Аватар URL для виведення

    class Config:
        from_attributes = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None,
            date: lambda v: v.isoformat() if v else None,
        }

class Token(BaseModel):
    """
    Схема для повернення JWT токену доступу.
    """
    access_token: str
    token_type: str

class RequestEmail(BaseModel):
    """
    Схема для запиту, що містить лише email (наприклад, для скидання пароля або повторного підтвердження).
    """
    email: EmailStr