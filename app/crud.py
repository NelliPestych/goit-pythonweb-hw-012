"""
Модуль, що містить функції для виконання CRUD-операцій
(Create, Read, Update, Delete) з даними в базі даних.
"""

from sqlalchemy.orm import Session
from sqlalchemy import and_
from app import models, schemas
from app.auth import get_password_hash
from datetime import date, datetime, timedelta
from typing import List, Optional

from app.models import UserRole

def create_user(db: Session, user: schemas.UserCreate) -> models.User:
    """Створює нового користувача в базі даних."""
    hashed_password = get_password_hash(user.password)
    db_user = models.User(email=user.email, hashed_password=hashed_password, role=UserRole.user)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def get_user_by_email(db: Session, email: str) -> Optional[models.User]:
    """Отримує користувача за email."""
    return db.query(models.User).filter(models.User.email == email).first()

def update_user_confirmation(db: Session, user: models.User, confirmed: bool) -> models.User:
    """Оновлює статус підтвердження email користувача."""
    user.confirmed = confirmed
    db.commit()
    db.refresh(user)
    return user

def update_user_avatar(db: Session, user_id: int, avatar_url: str) -> Optional[models.User]:
    """Оновлює URL аватара користувача."""
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user:
        user.avatar_url = avatar_url
        db.commit()
        db.refresh(user)
    return user

def create_contact(db: Session, contact: schemas.ContactCreate, user_id: int) -> models.Contact:
    """Створює новий контакт для вказаного користувача."""
    db_contact = models.Contact(**contact.model_dump(), user_id=user_id)
    db.add(db_contact)
    db.commit()
    db.refresh(db_contact)
    return db_contact

def get_contacts(db: Session, user_id: int, skip: int = 0, limit: int = 100) -> List[models.Contact]:
    """Отримує список контактів для вказаного користувача з пагінацією."""
    return db.query(models.Contact).filter(models.Contact.user_id == user_id).offset(skip).limit(limit).all()

def get_contact(db: Session, contact_id: int, user_id: int) -> Optional[models.Contact]:
    """Отримує один контакт за ID для вказаного користувача."""
    return db.query(models.Contact).filter(
        and_(models.Contact.id == contact_id, models.Contact.user_id == user_id)
    ).first()


def update_contact(db: Session, contact_id: int, contact: schemas.ContactUpdate, user_id: int) -> Optional[models.Contact]:
    """Оновлює існуючий контакт для вказаного користувача."""
    db_contact = db.query(models.Contact).filter(
        and_(models.Contact.id == contact_id, models.Contact.user_id == user_id)
    ).first()
    if db_contact:
        for key, value in contact.model_dump(exclude_unset=True).items():
            setattr(db_contact, key, value)
        db.commit()
        db.refresh(db_contact)
    return db_contact

def delete_contact(db: Session, contact_id: int, user_id: int) -> Optional[models.Contact]:
    """Видаляє контакт за ID для вказаного користувача."""
    db_contact = db.query(models.Contact).filter(
        and_(models.Contact.id == contact_id, models.Contact.user_id == user_id)
    ).first()
    if db_contact:
        db.delete(db_contact)
        db.commit()
    return db_contact

def search_contacts(db: Session, query: str, user_id: int) -> List[models.Contact]:
    """Шукає контакти за ім'ям, прізвищем або email для вказаного користувача."""
    search_pattern = f"%{query.lower()}%"
    return db.query(models.Contact).filter(
        and_(
            models.Contact.user_id == user_id,
            (
                models.Contact.first_name.ilike(search_pattern) |
                models.Contact.last_name.ilike(search_pattern) |
                models.Contact.email.ilike(search_pattern)
            )
        )
    ).all()


def upcoming_birthdays(db: Session, user_id: int) -> List[models.Contact]:
    """Отримує список контактів з днями народження, що наближаються (наступні 7 днів) для вказаного користувача."""
    today = date.today()
    upcoming_contacts = []

    contacts = db.query(models.Contact).filter(models.Contact.user_id == user_id).all()

    for contact in contacts:
        print(f"DEBUG: Processing contact: ID={contact.id}")
        print(f"DEBUG:   First Name: {contact.first_name} (Type: {type(contact.first_name)})")
        print(f"DEBUG:   Last Name: {contact.last_name} (Type: {type(contact.last_name)})")
        print(f"DEBUG:   Email: {contact.email} (Type: {type(contact.email)})")
        print(f"DEBUG:   Phone: {contact.phone} (Type: {type(contact.phone)})")
        print(f"DEBUG:   Birthday: {contact.birthday} (Type: {type(contact.birthday)})")
        print(f"DEBUG:   Additional Info: {contact.additional_info} (Type: {type(contact.additional_info)})")
        print(f"DEBUG:   Created At: {contact.created_at} (Type: {type(contact.created_at)})")
        print(f"DEBUG:   Updated At: {contact.updated_at} (Type: {type(contact.updated_at)})")


        birthday_this_year = contact.birthday.replace(year=today.year)
        if birthday_this_year < today:
            birthday_this_year = contact.birthday.replace(year=today.year + 1)

        delta = birthday_this_year - today
        if 0 <= delta.days <= 7:
            upcoming_contacts.append(contact)

    return upcoming_contacts