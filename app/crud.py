from sqlalchemy.orm import Session
from sqlalchemy import or_, func
from datetime import datetime, timedelta
from app import models, schemas
from app.auth import get_password_hash

def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()

def create_user(db: Session, user: schemas.UserCreate):
    hashed_password = get_password_hash(user.password)
    db_user = models.User(email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def update_user_confirmation(db: Session, user: models.User, confirmed: bool):
    user.confirmed = confirmed
    db.commit()
    db.refresh(user)
    return user

def create_contact(db: Session, contact: schemas.ContactCreate, user_id: int):
    db_contact = models.Contact(**contact.dict(), user_id=user_id)
    db.add(db_contact)
    db.commit()
    db.refresh(db_contact)
    return db_contact

def get_contacts(db: Session, skip: int = 0, limit: int = 100, user_id: int = None):
    query = db.query(models.Contact)
    if user_id is not None:
        query = query.filter(models.Contact.user_id == user_id)
    return query.offset(skip).limit(limit).all()

def get_contact(db: Session, contact_id: int, user_id: int = None):
    query = db.query(models.Contact).filter(models.Contact.id == contact_id)
    if user_id is not None:
        query = query.filter(models.Contact.user_id == user_id)
    return query.first()

def update_contact(db: Session, contact_id: int, updates: schemas.ContactUpdate, user_id: int = None):
    db_contact = get_contact(db, contact_id, user_id=user_id)
    if db_contact:
        if user_id is not None and db_contact.user_id != user_id:
            return None
        for field, value in updates.dict(exclude_unset=True).items():
            setattr(db_contact, field, value)
        db.commit()
        db.refresh(db_contact)
    return db_contact

def delete_contact(db: Session, contact_id: int, user_id: int = None):
    db_contact = get_contact(db, contact_id, user_id=user_id)
    if db_contact:
        if user_id is not None and db_contact.user_id != user_id:
            return None
        db.delete(db_contact)
        db.commit()
    return db_contact

def search_contacts(db: Session, query: str, user_id: int = None):
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
    today = datetime.today().date()
    upcoming = today + timedelta(days=7)

    query = db.query(models.Contact)
    if user_id is not None:
        query = query.filter(models.Contact.user_id == user_id)
    contacts = query.all()
    result = []

    for contact in contacts:
        bday_this_year = contact.birthday.replace(year=today.year)
        if today <= bday_this_year <= upcoming:
            result.append(contact)
        elif today.month == 12 and (bday_this_year.month == 1 or bday_this_year.month == 2):
            bday_next_year = contact.birthday.replace(year=today.year + 1)
            if today <= bday_next_year <= upcoming:
                result.append(contact)

    return result