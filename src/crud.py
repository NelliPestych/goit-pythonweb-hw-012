"""
Модуль, що містить функції для виконання CRUD-операцій
(Create, Read, Update, Delete) з даними в базі даних.
"""

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_ # Додано or_ для функції пошуку
from src import models, schemas
from src.auth import get_password_hash, verify_password # Додано verify_password для тестування
from datetime import date, datetime, timedelta
from typing import List, Optional

from src.models import UserRole, Contact

def create_user(db: Session, user: schemas.UserCreate) -> models.User:
    """
    Створює нового користувача в базі даних.

    Args:
        db (Session): Сесія бази даних.
        user (schemas.UserCreate): Схема даних для створення користувача.

    Returns:
        models.User: Створений об'єкт користувача.
    """
    hashed_password = get_password_hash(user.password)
    db_user = models.User(email=user.email, hashed_password=hashed_password, role=UserRole.user)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def get_user_by_email(db: Session, email: str) -> Optional[models.User]:
    """
    Отримує користувача за email.

    Args:
        db (Session): Сесія бази даних.
        email (str): Електронна пошта користувача.

    Returns:
        Optional[models.User]: Об'єкт користувача, якщо знайдено, інакше None.
    """
    return db.query(models.User).filter(models.User.email == email).first()

def update_user_confirmation(db: Session, user: models.User, confirmed: bool) -> models.User:
    """
    Оновлює статус підтвердження email користувача.

    Args:
        db (Session): Сесія бази даних.
        user (models.User): Об'єкт користувача для оновлення.
        confirmed (bool): Новий статус підтвердження (True/False).

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
        user_id (int): ID користувача, аватар якого потрібно оновити.
        avatar_url (str): Новий URL аватара.

    Returns:
        Optional[models.User]: Оновлений об'єкт користувача, якщо знайдено, інакше None.
    """
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user:
        user.avatar_url = avatar_url
        db.commit()
        db.refresh(user)
        return user
    return None

def create_contact(db: Session, contact: schemas.ContactCreate, user_id: int) -> models.Contact:
    """
    Створює новий контакт для вказаного користувача.

    Args:
        db (Session): Сесія бази даних.
        contact (schemas.ContactCreate): Схема даних для створення контакту.
        user_id (int): ID користувача, якому належить контакт.

    Returns:
        models.Contact: Створений об'єкт контакту.
    """
    db_contact = models.Contact(**contact.model_dump(), user_id=user_id)
    db.add(db_contact)
    db.commit()
    db.refresh(db_contact)
    return db_contact

def get_contacts(db: Session, user_id: int | None = None, skip: int = 0, limit: int = 100):
    """
        Отримує список контактів з пагінацією, опціонально фільтруючи за користувачем.

        Args:
            db (Session): Сесія бази даних.
            user_id (int | None): ID користувача, контакти якого потрібно отримати. Якщо None, повертає всі контакти.
            skip (int): Кількість записів для пропуску (для пагінації).
            limit (int): Максимальна кількість записів для повернення (для пагінації).

        Returns:
            List[models.Contact]: Список об'єктів контактів.
    """
    query = db.query(Contact)
    if user_id is not None:
        query = query.filter(Contact.user_id == user_id)
    return query.offset(skip).limit(limit).all()

def get_contact(db: Session, contact_id: int, user_id: int) -> Optional[models.Contact]:
    """
    Отримує конкретний контакт за ID для вказаного користувача.

    Args:
        db (Session): Сесія бази даних.
        contact_id (int): ID контакту, який потрібно отримати.
        user_id (int): ID користувача, якому належить контакт.

    Returns:
        Optional[models.Contact]: Об'єкт контакту, якщо знайдено, інакше None.
    """
    return db.query(models.Contact).filter(and_(models.Contact.id == contact_id, models.Contact.user_id == user_id)).first()

def update_contact(db: Session, contact_id: int, user_id: int, contact: schemas.ContactUpdate) -> Optional[models.Contact]:
    """
    Оновлює існуючий контакт для вказаного користувача.

    Args:
        db (Session): Сесія бази даних.
        contact_id (int): ID контакту, який потрібно оновити.
        user_id (int): ID користувача, якому належить контакт.
        contact (schemas.ContactUpdate): Схема даних з оновленою інформацією про контакт.

    Returns:
        Optional[models.Contact]: Оновлений об'єкт контакту, якщо знайдено, інакше None.
    """
    db_contact = db.query(models.Contact).filter(and_(models.Contact.id == contact_id, models.Contact.user_id == user_id)).first()
    if db_contact:
        for key, value in contact.model_dump(exclude_unset=True).items():
            setattr(db_contact, key, value)
        db.commit()
        db.refresh(db_contact)
        return db_contact
    return None

def delete_contact(db: Session, contact_id: int, user_id: int) -> Optional[models.Contact]:
    """
    Видаляє контакт для вказаного користувача.

    Args:
        db (Session): Сесія бази даних.
        contact_id (int): ID контакту, який потрібно видалити.
        user_id (int): ID користувача, якому належить контакт.

    Returns:
        Optional[models.Contact]: Видалений об'єкт контакту, якщо знайдено, інакше None.
    """
    db_contact = db.query(models.Contact).filter(and_(models.Contact.id == contact_id, models.Contact.user_id == user_id)).first()
    if db_contact:
        db.delete(db_contact)
        db.commit()
        return db_contact
    return None

def search_contacts(db: Session, query: str, user_id: int) -> List[models.Contact]:
    """
    Шукає контакти за ім'ям, прізвищем або email для вказаного користувача.
    Пошук нечутливий до регістру.

    Args:
        db (Session): Сесія бази даних.
        query (str): Рядок для пошуку.
        user_id (int): ID користувача, контакти якого потрібно шукати.

    Returns:
        List[models.Contact]: Список знайдених об'єктів контактів.
    """
    search_pattern = f"%{query.lower()}%"
    return db.query(models.Contact).filter(
        and_(
            models.Contact.user_id == user_id,
            or_(
                models.Contact.first_name.ilike(search_pattern),
                models.Contact.last_name.ilike(search_pattern),
                models.Contact.email.ilike(search_pattern)
            )
        )
    ).all()

def upcoming_birthdays(db: Session, user_id: int) -> List[models.Contact]:
    """
    Отримує список контактів з днями народження, що наближаються (наступні 7 днів) для вказаного користувача.

    Args:
        db (Session): Сесія бази даних.
        user_id (int): ID користувача, контакти якого потрібно перевірити.

    Returns:
        List[models.Contact]: Список об'єктів контактів з майбутніми днями народження.
    """
    today = date.today()
    upcoming_contacts = []

    contacts = db.query(models.Contact).filter(models.Contact.user_id == user_id).all()

    for contact in contacts:
        birthday_this_year = contact.birthday.replace(year=today.year)

        if birthday_this_year < today:
            birthday_next_year = contact.birthday.replace(year=today.year + 1)
            delta = (birthday_next_year - today).days
        else:
            delta = (birthday_this_year - today).days

        if 0 <= delta <= 7:
            upcoming_contacts.append(contact)

    # Сортуємо за днем народження для послідовності
    upcoming_contacts.sort(key=lambda c: c.birthday.month * 100 + c.birthday.day)
    return upcoming_contacts

def confirm_user_email(db: Session, user: models.User):
    """
        Підтверджує електронну пошту користувача.

        Args:
            db (Session): Сесія бази даних.
            user (models.User): Об'єкт користувача, чию пошту потрібно підтвердити.

        Returns:
            models.User: Оновлений об'єкт користувача з підтвердженим статусом.
    """
    user.confirmed = True
    db.commit()
    db.refresh(user)
    return user