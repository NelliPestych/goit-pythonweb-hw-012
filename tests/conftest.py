# tests/conftest.py
"""
Модуль для фікстур Pytest, що налаштовує тестове середовище.

Включає фікстури для тестової бази даних (SQLite), тестового клієнта FastAPI,
а також мокування сервісу відправки електронних листів.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient
from app.main import app
from app.database import Base
from app.deps import get_db
import os
from unittest.mock import AsyncMock, patch # Імпортуємо AsyncMock та patch

# Використовуємо SQLite для тестів для швидкості та ізоляції
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="session")
def db_engine():
    """
    Фікстура, що надає тестовий рушій бази даних.

    Створює таблиці на початку тестової сесії та видаляє їх після завершення.
    """
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine) # Очищуємо базу даних після всіх тестів

@pytest.fixture(scope="function")
def db_session(db_engine):
    """
    Фікстура, що надає сесію бази даних для кожного тесту.

    Використовує окрему транзакцію для кожного тесту та відкочує її
    після завершення тесту, забезпечуючи ізольоване середовище.
    """
    connection = db_engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)
    yield session
    session.close()
    transaction.rollback() # Відкат транзакції для чистого стану бази даних
    connection.close()

@pytest.fixture(scope="function")
def client(db_session):
    """
    Фікстура, що надає тестовий клієнт FastAPI.

    Перевизначає залежність `get_db` у FastAPI, щоб використовувати тестову сесію бази даних.
    """
    def override_get_db():
        try:
            yield db_session
        finally:
            db_session.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear() # Очищаємо перевизначення після тестів


@pytest.fixture(scope="function", autouse=True)
def mock_send_email():
    """
    Фікстура, що мокує функцію `send_email` у модулі `app.email`.

    Використовує `AsyncMock` для імітації асинхронної поведінки
    та `patch` для заміни реальної функції.
    `autouse=True` означає, що ця фікстура буде автоматично застосовуватися до всіх тестів.
    """
    with patch("app.email.FastMail", autospec=True) as mock_fastmail_cls:
        # Створюємо екземпляр mock FastMail та мокуємо його метод send_message
        mock_instance = AsyncMock()
        mock_fastmail_cls.return_value = mock_instance
        mock_instance.send_message = AsyncMock(return_value=None) # Метод send_message буде мокуватися

        yield mock_instance # Повертаємо mock-об'єкт, якщо тест захоче його використовувати