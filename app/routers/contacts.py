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
    return crud.create_contact(db, contact, user_id=current_user.id)

@router.get("/", response_model=List[schemas.ContactOut])
def read_all(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(deps.get_db),
    current_user: models.User = Depends(get_current_user)
):
    return crud.get_contacts(db, skip, limit, user_id=current_user.id)

@router.get("/search", response_model=List[schemas.ContactOut])
def search(
    query: str,
    db: Session = Depends(deps.get_db),
    current_user: models.User = Depends(get_current_user)
):
    return crud.search_contacts(db, query, user_id=current_user.id)

@router.get("/upcoming_birthdays", response_model=List[schemas.ContactOut])
def birthdays(
    db: Session = Depends(deps.get_db),
    current_user: models.User = Depends(get_current_user)
):
    return crud.upcoming_birthdays(db, user_id=current_user.id)

@router.get("/{contact_id}", response_model=schemas.ContactOut)
def read(
    contact_id: int,
    db: Session = Depends(deps.get_db),
    current_user: models.User = Depends(get_current_user)
):
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
    deleted_contact = crud.delete_contact(db, contact_id, user_id=current_user.id)
    if deleted_contact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Contact not found or not authorized")
    return deleted_contact