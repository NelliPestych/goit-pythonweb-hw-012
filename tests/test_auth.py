"""
Модуль для інтеграційних тестів маршрутів аутентифікації та
модуля app.auth.
"""

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from app import schemas
from app.auth import get_password_hash
import pytest
import asyncio

def test_create_user(client: TestClient, db_session: Session):
    """
    Тестує реєстрацію нового користувача через API ендпоінт.
    """
    response = client.post(
        "/api/auth/register",
        json={"email": "test_register@example.com", "password": "TestPassword123"}
    )
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "test_register@example.com"
    assert data["confirmed"] is False
    assert "id" in data
    assert "created_at" in data
    assert "updated_at" in data

    from app.crud import get_user_by_email
    user_in_db = get_user_by_email(db_session, "test_register@example.com")
    assert user_in_db is not None
    assert user_in_db.email == "test_register@example.com"
    assert user_in_db.confirmed is False


def test_register_existing_user(client: TestClient):
    """
    Тестує спробу реєстрації користувача з вже існуючим email.
    """
    client.post(
        "/api/auth/register",
        json={"email": "existing_reg@example.com", "password": "TestPassword123"}
    )

    response = client.post(
        "/api/auth/register",
        json={"email": "existing_reg@example.com", "password": "AnotherPassword456"}
    )
    assert response.status_code == 409  # Conflict
    assert response.json() == {"detail": "Account already exists"}


def test_login_user(client: TestClient, db_session: Session):
    """
    Тестує вхід користувача та отримання JWT токена.
    """
    email = "test_login@example.com"
    password = "TestPassword123"
    hashed_password = get_password_hash(password)
    user_model = schemas.UserCreate(email=email, password=password)
    from app.crud import create_user, update_user_confirmation
    user = create_user(db_session, user_model)
    update_user_confirmation(db_session, user, True)

    response = client.post(
        "/api/auth/login",
        data={"username": email, "password": password}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_login_user_unconfirmed_email(client: TestClient, db_session: Session):
    """
    Тестує вхід користувача з непідтвердженим email.
    """
    email = "unconfirmed_login@example.com"
    password = "TestPassword123"
    user_model = schemas.UserCreate(email=email, password=password)
    from app.crud import create_user
    create_user(db_session, user_model)

    response = client.post(
        "/api/auth/login",
        data={"username": email, "password": password}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Email not confirmed"


def test_login_user_invalid_credentials(client: TestClient, db_session: Session):
    """
    Тестує вхід з невірними обліковими даними.
    """
    email = "invalid_cred@example.com"
    password = "TestPassword123"
    user_model = schemas.UserCreate(email=email, password=password)
    from app.crud import create_user, update_user_confirmation
    user = create_user(db_session, user_model)
    update_user_confirmation(db_session, user, True)

    response = client.post(
        "/api/auth/login",
        data={"username": email, "password": "WrongPassword"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect email or password"

    response = client.post(
        "/api/auth/login",
        data={"username": "nonexistent@example.com", "password": "AnyPassword"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect email or password"


def test_confirm_email_valid_token(client: TestClient, db_session: Session):
    """
    Тестує підтвердження email за допомогою дійсного токена.
    """
    email = "confirm_valid@example.com"
    password = "TestPassword123"
    user_model = schemas.UserCreate(email=email, password=password)
    from app.crud import create_user, get_user_by_email
    user = create_user(db_session, user_model)

    from app.auth import create_email_verification_token
    token = create_email_verification_token({"sub": email})

    response = client.get(f"/api/auth/confirm_email/{token}")
    assert response.status_code == 200
    assert response.json()["message"] == "Email successfully confirmed"

    user_in_db = get_user_by_email(db_session, email)
    assert user_in_db.confirmed is True


def test_confirm_email_invalid_token(client: TestClient):
    """
    Тестує підтвердження email за допомогою недійсного або простроченого токена.
    """
    response = client.get("/api/auth/confirm_email/invalid_token_xyz")
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid or expired verification token"


def test_confirm_email_already_confirmed(client: TestClient, db_session: Session):
    """
    Тестує підтвердження вже підтвердженого email.
    """
    email = "already_confirmed@example.com"
    password = "TestPassword123"
    user_model = schemas.UserCreate(email=email, password=password)
    from app.crud import create_user, update_user_confirmation
    user = create_user(db_session, user_model)
    update_user_confirmation(db_session, user, True)

    from app.auth import create_email_verification_token
    token = create_email_verification_token({"sub": email})

    response = client.get(f"/api/auth/confirm_email/{token}")
    assert response.status_code == 200
    assert response.json()["message"] == "Your email is already confirmed"


@pytest.mark.asyncio
async def test_get_current_user_api(client: TestClient, db_session: Session):
    """
    Тестує отримання поточного користувача через API (інтеграційний тест).
    """
    email = "current_user_api@example.com"
    password = "TestPassword123"
    hashed_password = get_password_hash(password)
    user_model = schemas.UserCreate(email=email, password=password)
    from app.crud import create_user, update_user_confirmation
    user = create_user(db_session, user_model)
    update_user_confirmation(db_session, user, True)

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
    data = response.json()
    assert data["email"] == email
    assert data["confirmed"] is True
    assert "id" in data
