"""
Модуль для налаштування підключення до бази даних SQLAlchemy.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import os

SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@db:5432/contacts_db")

engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    """
    Dependency для отримання сесії бази даних.

    Yields:
        Session: Сесія бази даних.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_db_and_tables():
    """
    Створює всі таблиці в базі даних, визначені через Base.metadata.
    """
    from src import models
    Base.metadata.create_all(bind=engine)
    print("Database tables created successfully from create_db_and_tables.")