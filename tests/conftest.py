# conftest.py
"""
Модуль для фікстур Pytest, що налаштовує тестове середовище.

Включає фікстури для тестової бази даних (SQLite), тестового клієнта FastAPI,
а також мокування сервісу відправки електронних листів та клієнта Redis.
"""

import pytest
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch, MagicMock
from src.main import app
from src.deps import get_db

# Встановлюємо змінну середовища TESTING для тестів
os.environ["TESTING"] = "True"

# Імпортуємо модулі, щоб гарантовано зареєструвати всі моделі до create_all
import src.models

# Явно імпортуємо Base та моделі з src.models.
from src.models import Base, User, Contact

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
    print("DEBUG: Calling Base.metadata.create_all()...")
    Base.metadata.create_all(bind=engine)
    print("DEBUG: Base.metadata.create_all() finished.")
    yield engine
    print("DEBUG: Calling Base.metadata.drop_all()...")
    Base.metadata.drop_all(bind=engine)
    print("DEBUG: Base.metadata.drop_all() finished.")


@pytest.fixture(scope="function")
def db_session(db_engine):
    """
    Фікстура, що надає тестову сесію бази даних для кожного тесту.

    Відкочує всі зміни після завершення кожного тесту.
    """
    connection = db_engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)
    yield session
    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture(scope="function")
def client(db_session: Session):
    """
    Фікстура, що надає тестовий клієнт FastAPI з мокованими залежностями.
    """
    print("DEBUG: Setting up client fixture...")

    def override_get_db():
        try:
            yield db_session
        finally:
            db_session.close()

    mock_redis_instance = MagicMock()
    mock_redis_instance.get = AsyncMock(return_value=None)
    mock_redis_instance.setex = AsyncMock(return_value=True)
    mock_redis_instance.delete = AsyncMock(return_value=1)

    mock_get_redis_client_func = AsyncMock(return_value=mock_redis_instance)

    app.dependency_overrides[get_db] = override_get_db
    with patch("src.auth.get_redis_client", new=mock_get_redis_client_func):
        with TestClient(app) as c:
            yield c
    app.dependency_overrides.clear()


@pytest.fixture(scope="function", autouse=True)
def mock_send_email():
    """
    Фікстура, що мокує функцію `send_email` у модулі `src.email`.

    Використовує `AsyncMock` для імітації асинхронної поведінки
    та `patch` для заміни реальної функції.
    `autouse=True` означає, що ця фікстура буде автоматично застосовуватися до всіх тестів.
    """
    with patch("src.email.send_email", new_callable=AsyncMock) as mock_email:
        yield mock_email
