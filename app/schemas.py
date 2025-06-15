from pydantic import BaseModel, EmailStr
from datetime import date, datetime
from typing import Optional
from app.models import UserRole # Імпортуємо UserRole з models.py

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
    created_at: Optional[datetime]
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True
        # Додаємо JSON енкодери для обробки datetime та date об'єктів
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None,
            date: lambda v: v.isoformat() if v else None,
        }

class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    password: str

class UserLogin(UserBase):
    password: str

class UserOut(UserBase):
    id: int
    confirmed: bool
    created_at: Optional[datetime] # <--- Змінено на Optional[datetime]
    updated_at: Optional[datetime] # <--- Змінено на Optional[datetime]
    role: UserRole # Поле для ролі користувача

    class Config:
        from_attributes = True
        # Додаємо JSON енкодери для обробки datetime та date об'єктів у UserOut
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None, # <--- Додано if v else None
            date: lambda v: v.isoformat() if v else None, # <--- Додано if v else None
        }

class Token(BaseModel):
    access_token: str
    token_type: str
    refresh_token: Optional[str] = None


class RequestEmail(BaseModel):
    email: EmailStr

class PasswordReset(BaseModel):
    token: str
    new_password: str
