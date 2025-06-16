from pydantic import BaseModel, EmailStr, Field
from datetime import date, datetime
from typing import Optional
from app.models import UserRole

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
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None,
            date: lambda v: v.isoformat() if v else None,
        }

class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    password: str = Field(min_length=6) # ДОДАНО: Валідація мінімальної довжини пароля

class UserLogin(UserBase):
    password: str = Field(min_length=6) # ДОДАНО: Валідація мінімальної довжини пароля

# ДОДАНО: Нова схема для запиту скидання пароля, яка містить email та новий пароль
class PasswordResetRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6) # Це буде новий пароль


class UserOut(UserBase):
    id: int
    confirmed: bool
    created_at: Optional[datetime]
    updated_at: Optional[datetime]
    role: UserRole
    avatar_url: Optional[str] = None # ДОДАНО: Аватар URL для виведення

    class Config:
        from_attributes = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None,
            date: lambda v: v.isoformat() if v else None,
        }

class Token(BaseModel):
    access_token: str
    token_type: str

class RequestEmail(BaseModel):
    email: EmailStr