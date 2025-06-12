# app/routers/contacts.py
"""
Модуль для управління контактами користувачів.

Включає ендпоінти для створення, читання, оновлення та видалення контактів,
а також пошуку та перегляду майбутніх днів народження.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from app import schemas, crud, deps, models
from app.auth import get_current_user

router = APIRouter(prefix="/contacts", tags=["Contacts"])

@router.post("/", response_model=schemas.ContactOut, status_code=status.HTTP_201_CREATED)
def create(
    contact: schemas.ContactCreate,
    db: Session = Depends(deps.get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Створює новий контакт для поточного користувача.

    Args:
        contact (schemas.ContactCreate): Дані для створення контакту.
        db (Session): Сесія бази даних.
        current_user (models.User): Поточний аутентифікований користувач.

    Returns:
        schemas.ContactOut: Створений контакт.
    """
    return crud.create_contact(db, contact, user_id=current_user.id)

@router.get("/", response_model=List[schemas.ContactOut])
def read_all(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(deps.get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Отримує список усіх контактів для поточного користувача.

    Args:
        skip (int): Кількість контактів, які потрібно пропустити (для пагінації).
        limit (int): Максимальна кількість контактів для повернення (для пагінації).
        db (Session): Сесія бази даних.
        current_user (models.User): Поточний аутентифікований користувач.

    Returns:
        List[schemas.ContactOut]: Список контактів.
    """
    return crud.get_contacts(db, skip, limit, user_id=current_user.id)

@router.get("/search", response_model=List[schemas.ContactOut])
def search(
    query: str,
    db: Session = Depends(deps.get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Шукає контакти поточного користувача за іменем, прізвищем або електронною поштою.

    Args:
        query (str): Рядок для пошуку.
        db (Session): Сесія бази даних.
        current_user (models.User): Поточний аутентифікований користувач.

    Returns:
        List[schemas.ContactOut]: Список знайдених контактів.
    """
    return crud.search_contacts(db, query, user_id=current_user.id)

@router.get("/upcoming_birthdays", response_model=List[schemas.ContactOut])
def birthdays(
    db: Session = Depends(deps.get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Отримує список контактів поточного користувача, які матимуть день народження
    протягом найближчих 7 днів.

    Args:
        db (Session): Сесія бази даних.
        current_user (models.User): Поточний аутентифікований користувач.

    Returns:
        List[schemas.ContactOut]: Список контактів з майбутніми днями народження.
    """
    return crud.upcoming_birthdays(db, user_id=current_user.id)

@router.get("/{contact_id}", response_model=schemas.ContactOut)
def read(
    contact_id: int,
    db: Session = Depends(deps.get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Отримує контакт за його унікальним ідентифікатором для поточного користувача.

    Args:
        contact_id (int): Ідентифікатор контакту.
        db (Session): Сесія бази даних.
        current_user (models.User): Поточний аутентифікований користувач.

    Raises:
        HTTPException:
            - 404 NOT_FOUND: Якщо контакт не знайдено або поточний користувач не має до нього доступу.

    Returns:
        schemas.ContactOut: Знайдений контакт.
    """
    db_contact = crud.get_contact(db, contact_id, user_id=current_user.id)
    if db_contact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Contact not found or not authorized")
    return db_contact

@router.put("/{contact_id}", response_model=schemas.ContactOut)
def update(
    contact_id: int,
    contact: schemas.ContactUpdate,
    db: Session = Depends(deps.get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Оновлює існуючий контакт поточного користувача.

    Args:
        contact_id (int): Ідентифікатор контакту, який потрібно оновити.
        contact (schemas.ContactUpdate): Дані для оновлення контакту.
        db (Session): Сесія бази даних.
        current_user (models.User): Поточний аутентифікований користувач.

    Raises:
        HTTPException:
            - 404 NOT_FOUND: Якщо контакт не знайдено або поточний користувач не має до нього доступу.

    Returns:
        schemas.ContactOut: Оновлений контакт.
    """
    updated_contact = crud.update_contact(db, contact_id, contact, user_id=current_user.id)
    if updated_contact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Contact not found or not authorized")
    return updated_contact

@router.delete("/{contact_id}", response_model=schemas.ContactOut)
def delete(
    contact_id: int,
    db: Session = Depends(deps.get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Видаляє контакт поточного користувача за його ідентифікатором.

    Args:
        contact_id (int): Ідентифікатор контакту, який потрібно видалити.
        db (Session): Сесія бази даних.
        current_user (models.User): Поточний аутентифікований користувач.

    Raises:
        HTTPException:
            - 404 NOT_FOUND: Якщо контакт не знайдено або поточний користувач не має до нього доступу.

    Returns:
        schemas.ContactOut: Видалений контакт.
    """
    deleted_contact = crud.delete_contact(db, contact_id, user_id=current_user.id)
    if deleted_contact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Contact not found or not authorized")
    return deleted_contact