# app/crud.py
"""
Модуль, що містить функції Create, Read, Update, Delete (CRUD)
для взаємодії з базою даних через SQLAlchemy ORM.
"""

from sqlalchemy.orm import Session
from datetime import date
from typing import List, Optional
from sqlalchemy import and_ # Додано для використання and_ у фільтрах

from app import models, schemas
# Імпортуємо get_password_hash з app.auth для хешування пароля при створенні користувача
from app.auth import get_password_hash
from app.models import UserRole # Імпортуємо UserRole

# --- User CRUD operations ---

def get_user_by_email(db: Session, email: str):
    """
    Отримує користувача за email.

    Args:
        db (Session): Сесія бази даних.
        email (str): Email користувача.

    Returns:
        models.User: Об'єкт користувача або None, якщо не знайдено.
    """
    return db.query(models.User).filter(models.User.email == email).first()

def create_user(db: Session, user: schemas.UserCreate):
    """
    Створює нового користувача в базі даних, хешуючи його пароль.

    Args:
        db (Session): Сесія бази даних.
        user (schemas.UserCreate): Схема нового користувача (містить чистий пароль).

    Returns:
        models.User: Створений об'єкт користувача.
    """
    # Хешуємо пароль перед збереженням у базу даних
    hashed_password = get_password_hash(user.password)
    db_user = models.User(
        email=user.email,
        hashed_password=hashed_password,
        role=UserRole.user # Встановлюємо роль за замовчуванням
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def confirm_user_email(db: Session, user: models.User):
    """
    Підтверджує email користувача.

    Args:
        db (Session): Сесія бази даних.
        user (models.User): Об'єкт користувача, який потрібно підтвердити.
    """
    user.confirmed = True
    db.add(user)
    db.commit()
    db.refresh(user)

# --- Contact CRUD operations ---

def get_contacts(db: Session, user_id: Optional[int] = None, skip: int = 0, limit: int = 100):
    """
    Отримує список контактів.

    Args:
        db (Session): Сесія бази даних.
        user_id (Optional[int]): ID користувача, чиї контакти потрібно отримати.
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

def get_contact(db: Session, contact_id: int, user_id: int):
    """
    Отримує один контакт за його ID та ID користувача-власника.

    Args:
        db (Session): Сесія бази даних.
        contact_id (int): ID контакту.
        user_id (int): ID користувача-власника.

    Returns:
        models.Contact: Об'єкт контакту або None, якщо не знайдено.
    """
    return db.query(models.Contact).filter(
        and_(models.Contact.id == contact_id, models.Contact.user_id == user_id)
    ).first()

def create_contact(db: Session, contact: schemas.ContactCreate, user_id: int):
    """
    Створює новий контакт для вказаного користувача.

    Args:
        db (Session): Сесія бази даних.
        contact (schemas.ContactCreate): Схема нового контакту.
        user_id (int): ID користувача-власника.

    Returns:
        models.Contact: Створений об'єкт контакту.
    """
    db_contact = models.Contact(**contact.model_dump(), user_id=user_id) # Змінено на .model_dump() для Pydantic v2
    db.add(db_contact)
    db.commit()
    db.refresh(db_contact)
    return db_contact

def update_contact(db: Session, contact_id: int, user_id: int, contact: schemas.ContactUpdate):
    """
    Оновлює існуючий контакт.

    Args:
        db (Session): Сесія бази даних.
        contact_id (int): ID контакту для оновлення.
        user_id (int): ID користувача-власника.
        contact (schemas.ContactUpdate): Схема оновлених даних контакту.

    Returns:
        models.Contact: Оновлений об'єкт контакту або None, якщо контакт не знайдено.
    """
    db_contact = get_contact(db, contact_id, user_id)
    if db_contact:
        for key, value in contact.model_dump(exclude_unset=True).items(): # Змінено на .model_dump()
            setattr(db_contact, key, value)
        db.add(db_contact)
        db.commit()
        db.refresh(db_contact)
    return db_contact

def delete_contact(db: Session, contact_id: int, user_id: int):
    """
    Видаляє контакт.

    Args:
        db (Session): Сесія бази даних.
        contact_id (int): ID контакту для видалення.
        user_id (int): ID користувача-власника.

    Returns:
        models.Contact: Видалений об'єкт контакту або None, якщо контакт не знайдено.
    """
    db_contact = get_contact(db, contact_id, user_id)
    if db_contact:
        db.delete(db_contact)
        db.commit()
    return db_contact

def search_contacts(db: Session, user_id: int, query: str):
    """
    Шукає контакти за іменем, прізвищем або email.

    Args:
        db (Session): Сесія бази даних.
        user_id (int): ID користувача, чиї контакти потрібно шукати.
        query (str): Рядок запиту для пошуку.

    Returns:
        List[models.Contact]: Список знайдених контактів.
    """
    search_pattern = f"%{query.lower()}%"
    return db.query(models.Contact).filter(
        and_(
            models.Contact.user_id == user_id,
            (models.Contact.first_name.ilike(search_pattern)) |
            (models.Contact.last_name.ilike(search_pattern)) |
            (models.Contact.email.ilike(search_pattern))
        )
    ).all()

def get_upcoming_birthdays(db: Session, user_id: int):
    """
    Отримує контакти з днями народження протягом найближчих 7 днів.

    Args:
        db (Session): Сесія бази даних.
        user_id (int): ID користувача, чиї контакти потрібно перевірити.

    Returns:
        List[models.Contact]: Список контактів з найближчими днями народження.
    """
    today = date.today()
    upcoming_birthdays = []

    contacts = db.query(models.Contact).filter(models.Contact.user_id == user_id).all()

    for contact in contacts:
        contact_birthday = contact.birthday
        # Визначаємо поточний рік для дня народження
        current_year_birthday = contact_birthday.replace(year=today.year)

        # Якщо день народження вже пройшов цього року, перевіряємо наступний рік
        if current_year_birthday < today:
            current_year_birthday = current_year_birthday.replace(year=today.year + 1)

        delta = current_year_birthday - today
        if 0 <= delta.days <= 7:
            upcoming_birthdays.append(contact)

    return upcoming_birthdays
