"""
Модуль для інтеграційних тестів маршрутів аутентифікації та
модуля src.auth.
"""

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from src import schemas, models
from src.auth import get_password_hash, create_email_verification_token, create_password_reset_token, decode_password_reset_token
import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
import json
from src.database import get_db
from src import crud
from src.auth import get_redis_client
from datetime import timedelta, datetime, timezone
import os

@pytest.fixture
def mock_redis_instance(monkeypatch):
    mock = AsyncMock()
    monkeypatch.setattr("src.auth.get_redis_client", lambda: mock)
    return mock

# Тести для /api/auth/signup
@patch("src.email_utils.send_email", new_callable=AsyncMock)
def test_create_user(mock_send_email: AsyncMock, client: TestClient, db_session: Session):
    """
    Тестує реєстрацію нового користувача через API ендпоінт.
    """
    response = client.post(
        "/api/auth/signup",
        json={"email": "test_register@example.com", "password": "TestPassword123"}
    )
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "test_register@example.com"
    assert data["confirmed"] is False
    assert "id" in data
    assert "created_at" in data
    assert "updated_at" in data

    user_in_db = crud.get_user_by_email(db_session, "test_register@example.com")
    assert user_in_db is not None
    assert user_in_db.email == "test_register@example.com"
    assert user_in_db.confirmed is False

    if os.getenv("TESTING") == "false":
        mock_send_email.assert_awaited_once()

def test_register_existing_user(client: TestClient, db_session: Session, mock_send_email: AsyncMock):
    """
    Тестує спробу реєстрації користувача з уже існуючим email.
    """
    # Створюємо користувача напряму в базі даних
    existing_user_data = schemas.UserCreate(email="existing@example.com", password="Password123")
    crud.create_user(db_session, existing_user_data)

    response = client.post(
        "/api/auth/signup",
        json={"email": "existing@example.com", "password": "NewPassword456"}
    )
    assert response.status_code == 409 # Conflict
    assert response.json() == {"detail": "Account already exists"}
    mock_send_email.send_message.assert_not_called() # Переконуємось, що email не відправлявся

# Тести для /api/auth/login
def test_login_user_unconfirmed(client: TestClient, db_session: Session):
    """
    Тестує вхід користувача з непідтвердженим email.
    """
    email = "unconfirmed@example.com"
    password = "UnconfirmedPass123"
    user_data = schemas.UserCreate(email=email, password=password)
    crud.create_user(db_session, user_data)

    response = client.post(
        "/api/auth/login",
        data={"username": email, "password": password}
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Email not confirmed"}

def test_login_user_success(client: TestClient, db_session: Session):
    """
    Тестує успішний вхід користувача з підтвердженим email.
    """
    email = "confirmed_user@example.com"
    password = "ConfirmedPass123"
    user_data = schemas.UserCreate(email=email, password=password)
    user = crud.create_user(db_session, user_data)
    crud.update_user_confirmation(db_session, user, True) # Підтверджуємо email

    response = client.post(
        "/api/auth/login",
        data={"username": email, "password": password}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

def test_login_user_invalid_credentials(client: TestClient, db_session: Session):
    """
    Тестує вхід з невірними обліковими даними.
    """
    email = "invalid_cred@example.com"
    password = "InvalidCredPass"
    user_data = schemas.UserCreate(email=email, password=password)
    user = crud.create_user(db_session, user_data)
    crud.update_user_confirmation(db_session, user, True)

    response = client.post(
        "/api/auth/login",
        data={"username": email, "password": "WrongPassword"} # Неправильний пароль
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Incorrect email or password"}

    response = client.post(
        "/api/auth/login",
        data={"username": "non_existent@example.com", "password": "AnyPassword"} # Неіснуючий користувач
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Incorrect email or password"}

# Тести для /api/auth/confirm_email/{token}
def test_confirm_email_success(client: TestClient, db_session: Session, mock_send_email: AsyncMock):
    """
    Тестує успішне підтвердження email за токеном.
    """
    user_email = "confirm_me@example.com"
    user_password = "ConfirmPass123"
    user_data = schemas.UserCreate(email=user_email, password=user_password)
    user = crud.create_user(db_session, user_data)

    # Генеруємо токен підтвердження email (як це робиться в signup)
    token = create_email_verification_token({"sub": user_email})

    response = client.get(f"/api/auth/confirm_email/{token}")
    assert response.status_code == 200
    assert response.json() == {"message": "Email successfully confirmed"}

    updated_user = crud.get_user_by_email(db_session, user_email)
    assert updated_user.confirmed is True

def test_confirm_email_invalid_token(client: TestClient, db_session: Session):
    """
    Тестує підтвердження email з недійсним токеном.
    """
    response = client.get("/api/auth/confirm_email/invalid_token")
    assert response.status_code == 400
    assert "Could not validate credentials" in response.json()["detail"]

def test_confirm_email_expired_token(client: TestClient, db_session: Session):
    """
    Тестує підтвердження email з простроченим токеном.
    """
    user_email = "expired_token@example.com"
    user_data = schemas.UserCreate(email=user_email, password="ExpiredTokenPass")
    crud.create_user(db_session, user_data)

    # Створюємо прострочений токен
    expired_token = create_email_verification_token({"sub": user_email}, expires_delta=timedelta(minutes=-1))

    response = client.get(f"/api/auth/confirm_email/{expired_token}")
    assert response.status_code == 400
    assert "Could not validate credentials" in response.json()["detail"]

# Тести для /api/auth/request_email_confirmation
def test_request_email_confirmation_success(client: TestClient, db_session: Session, mock_send_email: AsyncMock):
    """
    Тестує успішний запит на повторне підтвердження email.
    """
    user_email = "resend_confirm@example.com"
    user_password = "ResendPass123"
    user_data = schemas.UserCreate(email=user_email, password=user_password)
    crud.create_user(db_session, user_data)
    db_session.commit()

    client.app.dependency_overrides[get_db] = lambda: db_session

    response = client.post(
        "/api/auth/request_email_confirmation",
        json={"email": user_email}
    )
    assert response.status_code == 200
    assert response.json() == {"message": "Confirmation email sent."}
    

def test_request_email_confirmation_already_confirmed(client: TestClient, db_session: Session, mock_send_email: AsyncMock):
    """
    Тестує запит на підтвердження email для вже підтвердженого користувача.
    """
    user_email = "already_confirmed@example.com"
    user_password = "AlreadyConfPass"
    user_data = schemas.UserCreate(email=user_email, password=user_password)
    user = crud.create_user(db_session, user_data)
    crud.update_user_confirmation(db_session, user, True)

    response = client.post(
        "/api/auth/request_email_confirmation",
        json={"email": user_email}
    )
    assert response.status_code == 409
    assert response.json() == {"detail": "Your email is already confirmed."}
    mock_send_email.send_message.assert_not_called()

def test_request_email_confirmation_user_not_found(client: TestClient, db_session: Session, mock_send_email: AsyncMock):
    """
    Тестує запит на підтвердження email для неіснуючого користувача.
    """
    response = client.post(
        "/api/auth/request_email_confirmation",
        json={"email": "non_existent_req@example.com"}
    )
    assert response.status_code == 404
    assert response.json() == {"detail": "Not Found"}
    mock_send_email.send_message.assert_not_called()

# Тести для /api/auth/request_password_reset
def test_request_password_reset_success(client: TestClient, db_session: Session, mock_send_email: AsyncMock):
    """
    Тестує успішний запит на скидання пароля.
    """
    user_email = "reset_user@example.com"
    user_password = "ResetPass123"
    user_data = schemas.UserCreate(email=user_email, password=user_password)
    user = crud.create_user(db_session, user_data)
    crud.update_user_confirmation(db_session, user, True)

    response = client.post(
        "/api/auth/request_reset_password",
        json={"email": user_email}
    )
    assert response.status_code == 200
    assert response.json() == {"message": "If a user with that email exists and is confirmed, a password reset link has been sent."}
    

def test_request_password_reset_unconfirmed_user(client: TestClient, db_session: Session, mock_send_email: AsyncMock):
    """
    Тестує запит на скидання пароля для непідтвердженого користувача.
    """
    user_email = "unconfirmed_reset@example.com"
    user_password = "UnconfirmedResetPass"
    user_data = schemas.UserCreate(email=user_email, password=user_password)
    crud.create_user(db_session, user_data) # Непідтверджений

    response = client.post(
        "/api/auth/request_reset_password",
        json={"email": user_email}
    )
    assert response.status_code == 403
    assert response.json() == {"detail": "Email not confirmed. Please confirm your email first."}
    mock_send_email.send_message.assert_not_called()

def test_request_password_reset_user_not_found(client: TestClient, db_session: Session, mock_send_email: AsyncMock):
    """
    Тестує запит на скидання пароля для неіснуючого користувача.
    """
    response = client.post(
        "/api/auth/request_reset_password",
        json={"email": "non_existent_reset@example.com"}
    )
    assert response.status_code == 404
    assert response.json() == {"detail": "Not Found"}
    mock_send_email.send_message.assert_not_called()

# Тести для /api/auth/reset_password/{token}
def test_reset_password_success(client: TestClient, db_session: Session, mock_send_email: AsyncMock):
    """
    Тестує успішне скидання пароля за токеном.
    """
    user_email = "user_to_reset@example.com"
    old_password = "OldPassword123"
    new_password = "NewSecurePassword456"

    user_data = schemas.UserCreate(email=user_email, password=old_password)
    user = crud.create_user(db_session, user_data)
    crud.update_user_confirmation(db_session, user, True)

    reset_token = create_password_reset_token({"sub": user_email})

    # Скидаємо пароль
    response = client.post(
        f"/api/auth/reset_password/{reset_token}",
        json={"email": user_email, "password": new_password} # Використовуємо UserLogin схему
    )
    assert response.status_code == 200
    assert response.json() == {"message": "Password has been successfully reset."}

    # Перевіряємо, чи можна увійти з новим паролем
    login_response = client.post(
        "/api/auth/login",
        data={"username": user_email, "password": new_password}
    )
    assert login_response.status_code == 200
    assert "access_token" in login_response.json()

    # Переконуємось, що старий пароль більше не працює
    failed_login_response = client.post(
        "/api/auth/login",
        data={"username": user_email, "password": old_password}
    )
    assert failed_login_response.status_code == 401

def test_reset_password_invalid_token(client: TestClient, db_session: Session):
    """
    Тестує скидання пароля з недійсним токеном.
    """
    user_email = "user_invalid_token@example.com"
    new_password = "NewPassword"
    user_data = schemas.UserCreate(email=user_email, password="OldPassword")
    user = crud.create_user(db_session, user_data)
    crud.update_user_confirmation(db_session, user, True)

    response = client.post(
        "/api/auth/reset_password/invalid_token_xyz",
        json={"email": user_email, "password": new_password}
    )
    assert response.status_code == 400
    assert "Could not validate credentials" in response.json()["detail"]

def test_reset_password_expired_token(client: TestClient, db_session: Session):
    """
    Тестує скидання пароля з простроченим токеном.
    """
    user_email = "user_expired_token@example.com"
    new_password = "NewPassword"
    user_data = schemas.UserCreate(email=user_email, password="OldPassword")
    user = crud.create_user(db_session, user_data)
    crud.update_user_confirmation(db_session, user, True)

    expired_token = create_password_reset_token({"sub": user_email}, expires_delta=timedelta(minutes=-1))

    response = client.post(
        f"/api/auth/reset_password/{expired_token}",
        json={"email": user_email, "password": new_password}
    )
    assert response.status_code == 400
    assert "Could not validate credentials" in response.json()["detail"]

def test_reset_password_mismatched_email(client: TestClient, db_session: Session):
    """
    Тестує скидання пароля, коли email у токені не збігається з наданим email.
    """
    user1_email = "user1@example.com"
    user2_email = "user2@example.com"
    user1_data = schemas.UserCreate(email=user1_email, password="User1Pass")
    user2_data = schemas.UserCreate(email=user2_email, password="User2Pass")
    crud.create_user(db_session, user1_data)
    crud.create_user(db_session, user2_data)
    crud.update_user_confirmation(db_session, crud.get_user_by_email(db_session, user1_email), True)
    crud.update_user_confirmation(db_session, crud.get_user_by_email(db_session, user2_email), True)

    token_for_user1 = create_password_reset_token({"sub": user1_email})

    response = client.post(
        f"/api/auth/reset_password/{token_for_user1}",
        json={"email": user2_email, "password": "NewPassForUser2"} # Спроба використати токен User1 для User2
    )
    assert response.status_code == 400
    assert response.json() == {"detail": "Email in token does not match provided email."}

def test_reset_password_user_not_found_after_token_decode(client: TestClient, db_session: Session):
    """
    Тестує скидання пароля, коли користувача не знайдено в БД після декодування токена.
    """
    non_existent_email = "deleted_user@example.com"
    token = create_password_reset_token({"sub": non_existent_email}) # Токен створено, але користувача немає в БД

    response = client.post(
        f"/api/auth/reset_password/{token}",
        json={"email": non_existent_email, "password": "NewPasswordXYZ"}
    )
    assert response.status_code == 404
    assert response.json() == {"detail": "User not found"}

# Тести для перевірки кешу Redis в get_current_user (додатково)
@pytest.mark.asyncio
async def test_get_current_user_from_redis_cache(client: TestClient, db_session: Session, mock_redis_instance: AsyncMock):
    """
    Тестує, що get_current_user отримує дані з кешу Redis, якщо вони там є.
    """
    email = "cached_user@example.com"
    password = "CachedPass123"
    user_data = schemas.UserCreate(email=email, password=password)
    user_db = crud.create_user(db_session, user_data)
    crud.update_user_confirmation(db_session, user_db, True)

    # Імітуємо збереження користувача в кеші Redis
    cached_user_dict = {
        "id": user_db.id,
        "email": user_db.email,
        "confirmed": user_db.confirmed,
        "created_at": user_db.created_at.isoformat(),
        "updated_at": user_db.updated_at.isoformat(),
        "role": user_db.role.value,
        "avatar_url": user_db.avatar_url
    }
    mock_redis_instance.get.return_value = json.dumps(cached_user_dict)

    client.app.dependency_overrides[get_redis_client] = lambda: mock_redis_instance

    # Логін, щоб отримати токен
    login_response = client.post(
        "/api/auth/login",
        data={"username": email, "password": password}
    )
    token = login_response.json()["access_token"]

    # Викликаємо захищений маршрут
    response = client.get(
        "/api/users/current_user",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json()["email"] == email
    mock_redis_instance.get.assert_called_once_with(f"user:{email}")

@pytest.mark.asyncio
async def test_get_current_user_from_db_and_cache_to_redis(client: TestClient, db_session: Session, mock_redis_instance: AsyncMock):
    """
    Тестує, що get_current_user отримує дані з БД, якщо немає в кеші, і потім кешує їх.
    """
    email = "db_to_cache_user@example.com"
    password = "DbToCachePass123"
    user_data = schemas.UserCreate(email=email, password=password)
    user_db = crud.create_user(db_session, user_data)
    crud.update_user_confirmation(db_session, user_db, True)

    mock_redis_instance.get.return_value = None # Імітуємо, що користувача немає в кеші

    client.app.dependency_overrides[get_redis_client] = lambda: mock_redis_instance

    login_response = client.post(
        "/api/auth/login",
        data={"username": email, "password": password}
    )
    token = login_response.json()["access_token"]

    response = client.get(
        "/api/users/current_user",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json()["email"] == email
    mock_redis_instance.get.assert_called_once_with(f"user:{email}")