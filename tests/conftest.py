# conftest.py
"""
Модуль для фікстур Pytest, що налаштовує тестове середовище.

Включає фікстури для тестової бази даних (SQLite), тестового клієнта FastAPI,
а також мокування сервісу відправки електронних листів та клієнта Redis.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from fastapi.testclient import TestClient
from app.main import app
from app.deps import get_db
import os
from unittest.mock import AsyncMock, patch, MagicMock

# ВАЖЛИВО: Явно імпортуємо Base та моделі з app.models.
# Це гарантує, що Base.metadata знає про всі моделі
# перед викликом Base.metadata.create_all().
from app.models import Base, User, Contact

# Встановлюємо змінну середовища TESTING для тестів
os.environ["TESTING"] = "True"


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

    # Створюємо мок-об'єкт, який буде імітувати клієнт Redis
    mock_redis_instance = MagicMock() # Загальний мок-об'єкт
    # Явно призначаємо AsyncMock для асинхронних методів Redis
    mock_redis_instance.get = AsyncMock(return_value=None)
    mock_redis_instance.setex = AsyncMock(return_value=True)
    mock_redis_instance.delete = AsyncMock(return_value=1)
    print(f"DEBUG: Created mock_redis_instance: {mock_redis_instance}")

    # Мокуємо функцію get_redis_client, яка є async функцією.
    # Вона має повертати awaitable, який, коли await'нути, дасть mock_redis_instance.
    mock_get_redis_client_func = AsyncMock(return_value=mock_redis_instance)
    print(f"DEBUG: Created mock_get_redis_client_func: {mock_get_redis_client_func}")

    app.dependency_overrides[get_db] = override_get_db
    with patch("app.auth.get_redis_client", new=mock_get_redis_client_func): # <-- ВИПРАВЛЕНО
        print(f"DEBUG: app.auth.get_redis_client is patched with: {mock_get_redis_client_func}")
        with TestClient(app) as c:
            yield c
    app.dependency_overrides.clear()

@pytest.fixture(scope="function", autouse=True)
def mock_send_email():
    """
    Фікстура, що мокує функцію `send_email` у модулі `app.email`.

    Використовує `AsyncMock` для імітації асинхронної поведінки
    та `patch` для заміни реальної функції.
    `autouse=True` означає, що ця фікстура буде автоматично застосовуватися до всіх тестів.
    """
    with patch("app.email.send_email", new_callable=AsyncMock) as mock_email:
        yield mock_email

# Прибрали mock_redis_client як autouse, оскільки тепер його мокування відбувається в `client` fixture
# @pytest.fixture(scope="function", autouse=True)
# def mock_redis_client():
#     """
#     Фікстура, що мокує функцію `get_redis_client` у модулі `app.auth`.
#
#     Це гарантує, що у всіх тестах, які викликають `get_redis_client`,
#     буде повертатися мок-об'єкт Redis з мокованими методами `get`, `setex`, `delete`.
#     """
#     with patch("app.auth.get_redis_client", new_callable=AsyncMock) as mock_get_redis:
#         mock_get_redis.return_value = MagicMock(spec=AsyncMock) # Mock the instance returned by get_redis_client
#         mock_get_redis.return_value.get.return_value = None
#         mock_get_redis.return_value.setex.return_value = True
#         mock_get_redis.return_value.delete.return_value = 1
#         yield mock_get_redis