"""
Модуль для інтеграційних тестів маршрутів користувачів (/api/users).
"""

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from src import schemas, crud, models
from src.auth import create_access_token
import pytest
from unittest.mock import patch
from src.models import UserRole
from src import auth as auth_utils

# --- Допоміжні функції для тестів ---
def create_test_user_and_get_token(client: TestClient, db_session: Session, email: str, password: str, is_admin: bool = False):
    user_data = schemas.UserCreate(email=email, password=password)
    user = crud.create_user(db_session, user_data)
    crud.update_user_confirmation(db_session, user, True)
    if is_admin:
        user.role = models.UserRole.admin
        db_session.commit()
        db_session.refresh(user)

    login_response = client.post(
        "/api/auth/login",
        data={"username": email, "password": password}
    )
    return user, login_response.json()["access_token"]

# --- Тести ---

def test_read_users_me_success(client: TestClient, db_session: Session):
    user, token = create_test_user_and_get_token(client, db_session, "me@example.com", "MySecretPass123")
    response = client.get("/api/users/current_user", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == user.email
    assert data["id"] == user.id
    assert data["confirmed"] is True
    assert data["role"] == models.UserRole.user.value
    assert "avatar_url" in data

def test_read_users_me_unauthenticated(client: TestClient):
    response = client.get("/api/users/current_user")
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"

def test_read_users_me_invalid_token(client: TestClient):
    response = client.get("/api/users/current_user", headers={"Authorization": "Bearer invalid_token"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Could not validate credentials"

def test_read_users_me_unconfirmed_email(client: TestClient, db_session: Session):
    email = "unconfirmed_me@example.com"
    password = "UnconfirmedPass"
    user_data = schemas.UserCreate(email=email, password=password)
    crud.create_user(db_session, user_data)
    login_response = client.post("/api/auth/login", data={"username": email, "password": password})
    assert login_response.status_code == 401
    assert login_response.json()["detail"] == "Email not confirmed"

def test_update_avatar_success(client: TestClient, db_session: Session):
    user, token = create_test_user_and_get_token(
        client, db_session, "avatar_success@example.com", "TestPass123", is_admin=True
    )

    with patch("cloudinary.uploader.upload", return_value={"secure_url": "https://mocked.cloudinary.com/avatar.jpg"}):
        with open("tests/test_avatar.png", "rb") as avatar:
            response = client.patch(
                "/api/users/avatar",
                files={"file": ("avatar.png", avatar, "image/png")},
                headers={"Authorization": f"Bearer {token}"}
            )
    assert response.status_code == 200

def test_update_avatar_no_file(client: TestClient, db_session: Session):
    user_data = schemas.UserCreate(email="avatar_no_file@example.com", password="TestPass123")
    user = crud.create_user(db_session, user_data)
    user.role = UserRole.admin
    crud.update_user_confirmation(db_session, user, True)
    db_session.commit()
    db_session.refresh(user)

    token = create_access_token(data={"sub": user.email})
    response = client.patch(
        "/api/users/avatar",
        files={},  # ключовий момент!
        headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "Avatar file is required."

def test_update_avatar_cloudinary_error(client: TestClient, db_session: Session, monkeypatch):
    user_data = schemas.UserCreate(email="avatar_cloudinary_fail@example.com", password="TestPass123")
    user = crud.create_user(db_session, user_data)
    user.role = UserRole.admin
    crud.update_user_confirmation(db_session, user, True)
    db_session.commit()
    db_session.refresh(user)

    token = create_access_token(data={"sub": user.email})

    def fake_upload(*args, **kwargs):
        raise Exception("Cloudinary failed")

    monkeypatch.setattr("cloudinary.uploader.upload", fake_upload)

    with open("tests/test_avatar.png", "rb") as avatar:
        response = client.patch(
            "/api/users/avatar",
            files={"file": ("avatar.png", avatar, "image/png")},
            headers={"Authorization": f"Bearer {token}"}
        )
    assert response.status_code == 500

def test_get_current_admin_user_forbidden(client: TestClient, db_session: Session):
    user_data = schemas.UserCreate(email="not_admin@example.com", password="TestPass123")
    user = crud.create_user(db_session, user_data)
    crud.update_user_confirmation(db_session, user, True)

    token = create_access_token(data={"sub": user.email})
    response = client.patch("/api/users/admin_only", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403
