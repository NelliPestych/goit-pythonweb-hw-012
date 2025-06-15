"""
Модуль, що визначає маршрути API для управління контактами.
"""

from typing import List, Optional
from datetime import date

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app import schemas, crud, deps, models
from app.auth import get_current_user

router = APIRouter(prefix="/contacts", tags=["Contacts"])


@router.post("/", response_model=schemas.ContactOut, status_code=status.HTTP_201_CREATED)
def create_contact(
    contact: schemas.ContactCreate,
    db: Session = Depends(deps.get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Створює новий контакт для поточного користувача.

    Args:
        contact (schemas.ContactCreate): Дані нового контакту.
        db (Session): Сесія бази даних.
        current_user (models.User): Поточний автентифікований користувач.

    Returns:
        schemas.ContactOut: Створений контакт.
    """
    return crud.create_contact(db=db, contact=contact, user_id=current_user.id)


@router.get("/", response_model=List[schemas.ContactOut])
def read_all(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    db: Session = Depends(deps.get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Отримує список усіх контактів поточного користувача з пагінацією.

    Args:
        skip (int): Кількість записів для пропуску.
        limit (int): Максимальна кількість записів для повернення.
        db (Session): Сесія бази даних.
        current_user (models.User): Поточний автентифікований користувач.

    Returns:
        List[schemas.ContactOut]: Список контактів.
    """
    return crud.get_contacts(db=db, user_id=current_user.id, skip=skip, limit=limit)


@router.get("/upcoming_birthdays", response_model=List[schemas.ContactOut])
def birthdays(
    db: Session = Depends(deps.get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Отримує список контактів поточного користувача з майбутніми днями народження
    (у наступні 7 днів).

    Args:
        db (Session): Сесія бази даних.
        current_user (models.User): Поточний автентифікований користувач.

    Returns:
        List[schemas.ContactOut]: Список контактів з майбутніми днями народження.
    """
    return crud.upcoming_birthdays(db, user_id=current_user.id)


@router.get("/{contact_id}", response_model=schemas.ContactOut)
def read_contact(
    contact_id: int,
    db: Session = Depends(deps.get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Отримує один контакт за його ID для поточного користувача.

    Args:
        contact_id (int): ID контакту.
        db (Session): Сесія бази даних.
        current_user (models.User): Поточний автентифікований користувач.

    Raises:
        HTTPException: 404 NOT_FOUND, якщо контакт не знайдено.

    Returns:
        schemas.ContactOut: Знайдений контакт.
    """
    db_contact = crud.get_contact(db, contact_id, user_id=current_user.id)
    if db_contact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Contact not found")
    return db_contact


@router.put("/{contact_id}", response_model=schemas.ContactOut)
def update_contact(
    contact_id: int,
    contact: schemas.ContactUpdate,
    db: Session = Depends(deps.get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Оновлює існуючий контакт за його ID для поточного користувача.

    Args:
        contact_id (int): ID контакту для оновлення.
        contact (schemas.ContactUpdate): Оновлені дані контакту.
        db (Session): Сесія бази даних.
        current_user (models.User): Поточний автентифікований користувач.

    Raises:
        HTTPException: 404 NOT_FOUND, якщо контакт не знайдено.

    Returns:
        schemas.ContactOut: Оновлений контакт.
    """
    updated_contact = crud.update_contact(db=db, contact_id=contact_id, contact=contact, user_id=current_user.id)
    if updated_contact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Contact not found")
    return updated_contact


@router.delete("/{contact_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_contact(
    contact_id: int,
    db: Session = Depends(deps.get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Видаляє контакт за його ID для поточного користувача.

    Args:
        contact_id (int): ID контакту для видалення.
        db (Session): Сесія бази даних.
        current_user (models.User): Поточний автентифікований користувач.

    Raises:
        HTTPException: 404 NOT_FOUND, якщо контакт не знайдено.

    Returns:
        None
    """
    db_contact = crud.delete_contact(db, contact_id, user_id=current_user.id)
    if db_contact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Contact not found")
    return {"message": "Contact deleted successfully"}


@router.get("/search/", response_model=List[schemas.ContactOut])
def search_contacts(
    query: str = Query(..., min_length=1),
    db: Session = Depends(deps.get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Шукає контакти поточного користувача за ім'ям, прізвищем або email.

    Args:
        query (str): Рядок для пошуку.
        db (Session): Сесія бази даних.
        current_user (models.User): Поточний автентифікований користувач.

    Returns:
        List[schemas.ContactOut]: Список знайдених контактів.
    """
    return crud.search_contacts(db, query, user_id=current_user.id)
