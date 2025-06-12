# app/crud.py
"""
Модуль, що містить функції для взаємодії з базою даних (CRUD операції)
для моделей User та Contact.
"""

from sqlalchemy.orm import Session
from sqlalchemy import or_, func
from datetime import datetime, timedelta
from app import models, schemas
from app.auth import get_password_hash

def get_user_by_email(db: Session, email: str):
    """
    Отримує користувача з бази даних за його електронною поштою.

    Args:
        db (Session): Сесія бази даних.
        email (str): Електронна пошта користувача.

    Returns:
        models.User | None: Об'єкт користувача, якщо знайдено, інакше None.
    """
    return db.query(models.User).filter(models.User.email == email).first()

def create_user(db: Session, user: schemas.UserCreate):
    """
    Створює нового користувача в базі даних.

    Пароль користувача хешується перед збереженням.

    Args:
        db (Session): Сесія бази даних.
        user (schemas.UserCreate): Схема Pydantic з даними для створення користувача.

    Returns:
        models.User: Об'єкт щойно створеного користувача.
    """
    hashed_password = get_password_hash(user.password)
    db_user = models.User(email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def update_user_confirmation(db: Session, user: models.User, confirmed: bool):
    """
    Оновлює статус підтвердження електронної пошти користувача.

    Args:
        db (Session): Сесія бази даних.
        user (models.User): Об'єкт користувача, який потрібно оновити.
        confirmed (bool): Новий статус підтвердження (True/False).

    Returns:
        models.User: Оновлений об'єкт користувача.
    """
    user.confirmed = confirmed
    db.commit()
    db.refresh(user)
    return user

def create_contact(db: Session, contact: schemas.ContactCreate, user_id: int):
    """
    Створює новий контакт у базі даних для вказаного користувача.

    Args:
        db (Session): Сесія бази даних.
        contact (schemas.ContactCreate): Схема Pydantic з даними для створення контакту.
        user_id (int): ID користувача, який створює контакт.

    Returns:
        models.Contact: Об'єкт щойно створеного контакту.
    """
    db_contact = models.Contact(**contact.dict(), user_id=user_id)
    db.add(db_contact)
    db.commit()
    db.refresh(db_contact)
    return db_contact

def get_contacts(db: Session, skip: int = 0, limit: int = 100, user_id: int = None):
    """
    Отримує список контактів з бази даних.

    Забезпечує пагінацію та фільтрацію за ID користувача, якщо він вказаний.

    Args:
        db (Session): Сесія бази даних.
        skip (int): Кількість записів, які потрібно пропустити.
        limit (int): Максимальна кількість записів для повернення.
        user_id (int | None): ID користувача, чиї контакти потрібно отримати. Якщо None, повертає всі контакти.

    Returns:
        List[models.Contact]: Список об'єктів контактів.
    """
    query = db.query(models.Contact)
    if user_id is not None:
        query = query.filter(models.Contact.user_id == user_id)
    return query.offset(skip).limit(limit).all()

def get_contact(db: Session, contact_id: int, user_id: int = None):
    """
    Отримує контакт за його ID.

    Може фільтрувати за ID користувача для забезпечення належності.

    Args:
        db (Session): Сесія бази даних.
        contact_id (int): ID контакту.
        user_id (int | None): ID користувача, якому належить контакт.

    Returns:
        models.Contact | None: Об'єкт контакту, якщо знайдено та належить користувачу, інакше None.
    """
    query = db.query(models.Contact).filter(models.Contact.id == contact_id)
    if user_id is not None:
        query = query.filter(models.Contact.user_id == user_id)
    return query.first()

def update_contact(db: Session, contact_id: int, updates: schemas.ContactUpdate, user_id: int = None):
    """
    Оновлює існуючий контакт у базі даних.

    Args:
        db (Session): Сесія бази даних.
        contact_id (int): ID контакту, який потрібно оновити.
        updates (schemas.ContactUpdate): Схема Pydantic з полями, які потрібно оновити.
        user_id (int | None): ID користувача, якому належить контакт.

    Returns:
        models.Contact | None: Оновлений об'єкт контакту, якщо знайдено та оновлено, інакше None.
    """
    db_contact = get_contact(db, contact_id, user_id=user_id)
    if db_contact:
        if user_id is not None and db_contact.user_id != user_id:
            return None # Користувач не має дозволу на оновлення цього контакту
        for field, value in updates.dict(exclude_unset=True).items():
            setattr(db_contact, field, value)
        db.commit()
        db.refresh(db_contact)
    return db_contact

def delete_contact(db: Session, contact_id: int, user_id: int = None):
    """
    Видаляє контакт з бази даних.

    Args:
        db (Session): Сесія бази даних.
        contact_id (int): ID контакту, який потрібно видалити.
        user_id (int | None): ID користувача, якому належить контакт.

    Returns:
        models.Contact | None: Видалений об'єкт контакту, якщо знайдено та видалено, інакше None.
    """
    db_contact = get_contact(db, contact_id, user_id=user_id)
    if db_contact:
        if user_id is not None and db_contact.user_id != user_id:
            return None # Користувач не має дозволу на видалення цього контакту
        db.delete(db_contact)
        db.commit()
    return db_contact

def search_contacts(db: Session, query: str, user_id: int = None):
    """
    Шукає контакти за частиною імені, прізвища або електронної пошти.

    Пошук не чутливий до регістру.

    Args:
        db (Session): Сесія бази даних.
        query (str): Рядок пошукового запиту.
        user_id (int | None): ID користувача, чиї контакти потрібно шукати.

    Returns:
        List[models.Contact]: Список знайдених контактів.
    """
    filters = or_(
        models.Contact.first_name.ilike(f"%{query}%"),
        models.Contact.last_name.ilike(f"%{query}%"),
        models.Contact.email.ilike(f"%{query}%")
    )
    search_query = db.query(models.Contact).filter(filters)
    if user_id is not None:
        search_query = search_query.filter(models.Contact.user_id == user_id)
    return search_query.all()

def upcoming_birthdays(db: Session, user_id: int = None):
    """
    Знаходить контакти з майбутніми днями народження (протягом наступних 7 днів).

    Дні народження порівнюються лише за місяцем та днем, ігноруючи рік народження.
    Враховує перехід через кінець року (грудень/січень).

    Args:
        db (Session): Сесія бази даних.
        user_id (int | None): ID користувача, чиї контакти потрібно перевіряти.

    Returns:
        List[models.Contact]: Список контактів з найближчими днями народження.
    """
    today = datetime.today().date()
    upcoming = today + timedelta(days=7)

    query = db.query(models.Contact)
    if user_id is not None:
        query = query.filter(models.Contact.user_id == user_id)
    contacts = query.all()
    result = []

    for contact in contacts:
        # Замінюємо рік народження контакту на поточний рік, щоб порівнювати місяць та день
        bday_this_year = contact.birthday.replace(year=today.year)
        if today <= bday_this_year <= upcoming:
            result.append(contact)
        # Обробка днів народження, що припадають на наступний рік, якщо поточний період охоплює кінець року
        elif today.month == 12 and (bday_this_year.month == 1 or bday_this_year.month == 2):
            bday_next_year = contact.birthday.replace(year=today.year + 1)
            if today <= bday_next_year <= upcoming:
                result.append(contact)

    return result