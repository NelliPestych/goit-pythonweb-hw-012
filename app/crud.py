# app/crud.py
"""
Модуль, що містить функції для виконання CRUD-операцій
(Create, Read, Update, Delete) з даними в базі даних.
"""

from sqlalchemy.orm import Session
from sqlalchemy import and_
from app import models, schemas
from app.auth import get_password_hash  # Імпортуємо функцію хешування пароля
from datetime import date, datetime, timedelta
from typing import List, Optional

# Імпортуємо UserRole з models, оскільки вона там визначена як Enum
from app.models import UserRole


def create_user(db: Session, user: schemas.UserCreate) -> models.User:
    """
    Створює нового користувача в базі даних.

    Args:
        db (Session): Сесія бази даних.
        user (schemas.UserCreate): Схема даних нового користувача.

    Returns:
        models.User: Створений об'єкт користувача.
    """
    hashed_password = get_password_hash(user.password)
    # Присвоюємо роль за замовчуванням при створенні користувача
    db_user = models.User(email=user.email, hashed_password=hashed_password, role=UserRole.user)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def get_user_by_email(db: Session, email: str) -> Optional[models.User]:
    """
    Отримує користувача з бази даних за електронною поштою.

    Args:
        db (Session): Сесія бази даних.
        email (str): Електронна пошта користувача.

    Returns:
        Optional[models.User]: Об'єкт користувача або None, якщо користувача не знайдено.
    """
    return db.query(models.User).filter(models.User.email == email).first()


def update_user_confirmation(db: Session, user: models.User, confirmed: bool) -> models.User:
    """
    Оновлює статус підтвердження електронної пошти користувача.

    Args:
        db (Session): Сесія бази даних.
        user (models.User): Об'єкт користувача.
        confirmed (bool): Новий статус підтвердження.

    Returns:
        models.User: Оновлений об'єкт користувача.
    """
    user.confirmed = confirmed
    db.commit()
    db.refresh(user)
    return user


def update_user_avatar(db: Session, user_id: int, avatar_url: str) -> Optional[models.User]:
    """
    Оновлює URL аватара користувача.

    Args:
        db (Session): Сесія бази даних.
        user_id (int): ID користувача.
        avatar_url (str): Новий URL аватара.

    Returns:
        Optional[models.User]: Оновлений об'єкт користувача або None, якщо користувача не знайдено.
    """
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user:
        user.avatar_url = avatar_url
        db.commit()
        db.refresh(user)
    return user


def create_contact(db: Session, contact: schemas.ContactCreate, user_id: int) -> models.Contact:
    """
    Створює новий контакт для вказаного користувача.

    Args:
        db (Session): Сесія бази даних.
        contact (schemas.ContactCreate): Схема даних нового контакту.
        user_id (int): ID користувача-власника.

    Returns:
        models.Contact: Створений об'єкт контакту.
    """
    db_contact = models.Contact(**contact.model_dump(), user_id=user_id)  # Використовуємо .model_dump()
    db.add(db_contact)
    db.commit()
    db.refresh(db_contact)
    return db_contact


def get_contacts(db: Session, user_id: Optional[int] = None, skip: int = 0, limit: int = 100) -> List[models.Contact]:
    """
    Отримує список контактів.

    Args:
        db (Session): Сесія бази даних.
        user_id (Optional[int]): ID користувача, якщо потрібно отримати контакти конкретного користувача.
                                 Якщо None, повертає всі контакти (використовується для тестів/адміна).
        skip (int): Кількість записів для пропуску.
        limit (int): Максимальна кількість записів для повернення.

    Returns:
        List[models.Contact]: Список об'єктів контактів.
    """
    query = db.query(models.Contact)
    if user_id:
        query = query.filter(models.Contact.user_id == user_id)
    return query.offset(skip).limit(limit).all()


def get_contact(db: Session, contact_id: int, user_id: int) -> Optional[models.Contact]:
    """
    Отримує один контакт за його ID та ID користувача.

    Args:
        db (Session): Сесія бази даних.
        contact_id (int): ID контакту.
        user_id (int): ID користувача-власника.

    Returns:
        Optional[models.Contact]: Об'єкт контакту або None, якщо контакт не знайдено
                                 або він не належить цьому користувачу.
    """
    return db.query(models.Contact).filter(
        and_(models.Contact.id == contact_id, models.Contact.user_id == user_id)
    ).first()


def update_contact(db: Session, contact_id: int, contact: schemas.ContactUpdate, user_id: int) -> Optional[
    models.Contact]:
    """
    Оновлює існуючий контакт.

    Args:
        db (Session): Сесія бази даних.
        contact_id (int): ID контакту, який потрібно оновити.
        contact (schemas.ContactUpdate): Схема даних для оновлення контакту.
        user_id (int): ID користувача-власника.

    Returns:
        Optional[models.Contact]: Оновлений об'єкт контакту або None, якщо контакт не знайдено
                                 або він не належить цьому користувачу.
    """
    db_contact = db.query(models.Contact).filter(
        and_(models.Contact.id == contact_id, models.Contact.user_id == user_id)
    ).first()
    if db_contact:
        # Оновлюємо тільки ті поля, які були надані в схемі оновлення
        for key, value in contact.model_dump(exclude_unset=True).items():  # Використовуємо exclude_unset=True
            setattr(db_contact, key, value)
        db.commit()
        db.refresh(db_contact)
    return db_contact


def delete_contact(db: Session, contact_id: int, user_id: int) -> Optional[models.Contact]:
    """
    Видаляє контакт.

    Args:
        db (Session): Сесія бази даних.
        contact_id (int): ID контакту, який потрібно видалити.
        user_id (int): ID користувача-власника.

    Returns:
        Optional[models.Contact]: Видалений об'єкт контакту або None, якщо контакт не знайдено
                                 або він не належить цьому користувачу.
    """
    db_contact = db.query(models.Contact).filter(
        and_(models.Contact.id == contact_id, models.Contact.user_id == user_id)
    ).first()
    if db_contact:
        db.delete(db_contact)
        db.commit()
    return db_contact


def search_contacts(db: Session, query: str, user_id: int) -> List[models.Contact]:
    """
    Шукає контакти за ім'ям, прізвищем або електронною поштою.

    Args:
        db (Session): Сесія бази даних.
        query (str): Рядок пошуку.
        user_id (int): ID користувача-власника.

    Returns:
        List[models.Contact]: Список знайдених контактів.
    """
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
    """
    Отримує список контактів з днями народження, що наближаються (наступні 7 днів).

    Args:
        db (Session): Сесія бази даних.
        user_id (int): ID користувача-власника.

    Returns:
        List[models.Contact]: Список контактів з майбутніми днями народження.
    """
    today = date.today()
    upcoming_contacts = []

    contacts = db.query(models.Contact).filter(models.Contact.user_id == user_id).all()

    for contact in contacts:
        birthday_this_year = contact.birthday.replace(year=today.year)
        if birthday_this_year < today:
            birthday_this_year = contact.birthday.replace(year=today.year + 1)

        delta = birthday_this_year - today
        if 0 <= delta.days <= 7:
            upcoming_contacts.append(contact)

    return upcoming_contacts