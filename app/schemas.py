from pydantic import BaseModel, EmailStr
from datetime import date, datetime
from typing import Optional
from app.models import UserRole  # Імпортуємо UserRole з models.py, або визначимо тут Enum


# Якщо ви не хочете імпортувати з models, можна перевизначити Enum тут:
# import enum
# class UserRole(str, enum.Enum):
#     user = "user"
#     admin = "admin"

class ContactBase(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    phone: str
    birthday: date
    additional_info: Optional[str] = None


class ContactCreate(ContactBase):
    pass


class ContactUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    birthday: Optional[date] = None
    additional_info: Optional[str] = None


class ContactOut(ContactBase):
    id: int

    class Config:
        from_attributes = True


class UserBase(BaseModel):
    email: EmailStr


class UserCreate(UserBase):
    password: str


class UserLogin(UserBase):
    password: str


class UserOut(UserBase):
    id: int
    confirmed: bool
    created_at: datetime
    updated_at: datetime
    role: UserRole  # <--- ДОДАНО: поле для ролі користувача

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str


class RequestEmail(BaseModel):
    email: EmailStr


class PasswordReset(BaseModel):
    token: str
    new_password: str
