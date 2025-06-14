# app/models.py
"""
Модуль, що визначає моделі SQLAlchemy для Contacts App,
включаючи моделі User та Contact.
"""

from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Date, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
import enum

Base = declarative_base()

# Визначення переліку для ролей користувачів
class UserRole(enum.Enum):
    user = "user"
    admin = "admin"

class User(Base):
    """
    Модель користувача.

    Атрибути:
        id (int): Унікальний ідентифікатор користувача.
        email (str): Електронна пошта користувача (унікальна).
        hashed_password (str): Хешований пароль користувача.
        confirmed (bool): Статус підтвердження електронної пошти.
        created_at (datetime): Час створення облікового запису.
        updated_at (datetime): Час останнього оновлення облікового запису.
        avatar_url (str): URL аватара користувача (для Cloudinary).
        role (UserRole): Роль користувача (user або admin).
        contacts (relationship): Зв'язок з контактами, що належать цьому користувачу.
    """
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    confirmed = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    avatar_url = Column(String, nullable=True) # Поле для URL аватара
    # Додаємо поле role з типом Enum
    role = Column(Enum(UserRole), default=UserRole.user, nullable=False)

    contacts = relationship("Contact", back_populates="owner")

class Contact(Base):
    """
    Модель контакту.

    Атрибути:
        id (int): Унікальний ідентифікатор контакту.
        first_name (str): Ім'я контакту.
        last_name (str): Прізвище контакту.
        email (str): Електронна пошта контакту (унікальна для користувача).
        phone (str): Номер телефону контакту.
        birthday (Date): Дата народження контакту.
        additional_info (str): Додаткова інформація про контакт.
        user_id (int): Ідентифікатор користувача-власника контакту (зовнішній ключ).
        created_at (datetime): Час створення контакту.
        updated_at (datetime): Час останнього оновлення контакту.
        owner (relationship): Зв'язок з користувачем-власником.
    """
    __tablename__ = "contacts"
    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String, index=True, nullable=False)
    last_name = Column(String, index=True, nullable=False)
    email = Column(String, unique=False, index=True, nullable=False) # email тепер не унікальний глобально
    phone = Column(String, unique=False, nullable=False)
    birthday = Column(Date, nullable=False)
    additional_info = Column(String, nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    owner = relationship("User", back_populates="contacts")