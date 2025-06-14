# app/database.py
"""
Модуль для налаштування підключення до бази даних SQLAlchemy.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import os

# Зчитуємо URL бази даних зі змінних середовища
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@db:5432/contacts_db")

# Створюємо SQLAlchemy двигун
engine = create_engine(SQLALCHEMY_DATABASE_URL)

# Налаштовуємо фабрику сесій
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Базовий клас для декларативних моделей
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
    # Це імпорт має бути тут, щоб уникнути циклічних залежностей
    # і гарантувати, що моделі визначені перед створенням таблиць.
    from app import models
    Base.metadata.create_all(bind=engine)
    print("Database tables created successfully from create_db_and_tables.")