"""
Модуль для управління залежностями, такими як сесія бази даних.
"""

from src.database import SessionLocal
from fastapi import Depends
from sqlalchemy.orm import Session

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
