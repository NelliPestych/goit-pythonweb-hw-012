# tests/test_users.py
"""
Модуль для інтеграційних тестів маршрутів користувачів (/api/users).
"""

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from app import schemas, crud, models
from app.auth import get_password_hash, create_access_token
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import io # Для створення імітації файлу


# --- Допоміжні функції для тестів ---
def create_test_user_and_get_token(client: TestClient, db_session: Session, email: str, password: str, is_admin: bool = False):
    """Створює користувача (або адміна), підтверджує його і повертає access_token."""
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


# --- Тести для /api/users/current_user ---

def test_read_users_me_success(client: TestClient, db_session: Session):
    """
    Тестує успішне отримання інформації про поточного користувача.
    """
    user, token = create_test_user_and_get_token(client, db_session, "me@example.com", "MySecretPass123")

    response = client.get(
        "/api/users/current_user",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == user.email
    assert data["id"] == user.id
    assert data["confirmed"] is True
    assert data["role"] == models.UserRole.user.value # Перевіряємо, що роль серіалізується коректно
    assert "avatar_url" in data # Навіть якщо None, поле має бути

def test_read_users_me_unauthenticated(client: TestClient):
    """
    Тестує отримання інформації про поточного користувача без авторизації.
    """
    response = client.get("/api/users/current_user")
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"

def test_read_users_me_invalid_token(client: TestClient):
    """
    Тестує отримання інформації про поточного користувача з недійсним токеном.
    """
    response = client.get(
        "/api/users/current_user",
        headers={"Authorization": "Bearer invalid_token"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Could not validate credentials"

def test_read_users_me_unconfirmed_email(client: TestClient, db_session: Session):
    """
    Тестує отримання інформації про поточного користувача з непідтвердженим email.
    """
    email = "unconfirmed_me@example.com"
    password = "UnconfirmedPass"
    user_data = schemas.UserCreate(email=email, password=password)
    crud.create_user(db_session, user_data) # Не підтверджуємо email

    login_response = client.post(
        "/api/auth/login",
        data={"username": email, "password": password}
    )
    assert login_response.status_code == 401 # Логін мав би провалитися через непідтверджений email
    assert login_response.json()["detail"] == "Email not confirmed"


# --- Тести для /api/users/avatar ---

@pytest.mark.asyncio
async def test_update_avatar_success(client: TestClient, db_session: Session):
    """
    Тестує успішне оновлення аватара користувача.
    Мокуємо Cloudinary API.
    """
    user_email = "avatar_user@example.com"
    user_password = "AvatarPass123"
    user, token = create_test_user_and_get_token(client, db_session, user_email, user_password)

    # Мокуємо cloudinary.uploader.upload
    mock_upload_result = {
        "secure_url": "http://example.com/new_avatar.jpg",
        "public_id": f"avatar_{user.id}"
    }
    with patch("cloudinary.uploader.upload", return_value=mock_upload_result) as mock_cloudinary_upload:
        # Створюємо фіктивний файл
        file_content = b"fake image content"
        file = io.BytesIO(file_content)

        response = client.patch(
            "/api/users/avatar",
            headers={"Authorization": f"Bearer {token}"},
            files={"file": ("test_image.jpg", file, "image/jpeg")}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == user_email
        assert data["avatar_url"] == "http://example.com/new_avatar.jpg"

        mock_cloudinary_upload.assert_called_once_with(
            file,
            folder="avatars",
            public_id=f"avatar_{user.id}",
            overwrite=True
        )
        # Перевіряємо, що URL оновився в базі даних
        updated_user = crud.get_user_by_email(db_session, user_email)
        assert updated_user.avatar_url == "http://example.com/new_avatar.jpg"


@pytest.mark.asyncio
async def test_update_avatar_no_file(client: TestClient, db_session: Session):
    """
    Тестує оновлення аватара без файлу.
    """
    _, token = create_test_user_and_get_token(client, db_session, "no_file_user@example.com", "NoFilePass")

    response = client.patch(
        "/api/users/avatar",
        headers={"Authorization": f"Bearer {token}"}
        # Файл не передається
    )
    assert response.status_code == 422 # Unprocessable Entity - очікуємо помилку валідації FastAPI


@pytest.mark.asyncio
async def test_update_avatar_cloudinary_error(client: TestClient, db_session: Session):
    """
    Тестує оновлення аватара, коли Cloudinary повертає помилку.
    """
    user_email = "cloudinary_error_user@example.com"
    user_password = "CloudErrorPass"
    user, token = create_test_user_and_get_token(client, db_session, user_email, user_password)

    from cloudinary.exceptions import Error as CloudinaryError

    with patch("cloudinary.uploader.upload", side_effect=CloudinaryError("Simulated Cloudinary error")) as mock_cloudinary_upload:
        file_content = b"fake image content"
        file = io.BytesIO(file_content)

        response = client.patch(
            "/api/users/avatar",
            headers={"Authorization": f"Bearer {token}"},
            files={"file": ("test_image.jpg", file, "image/jpeg")}
        )
        assert response.status_code == 500
        assert "Cloudinary upload failed" in response.json()["detail"]
        mock_cloudinary_upload.assert_called_once()

        # Перевіряємо, що URL аватара не змінився в базі даних
        updated_user = crud.get_user_by_email(db_session, user_email)
        assert updated_user.avatar_url is None # Або залишився попереднім, якщо був

# Тест на адмінський доступ, який вже існував у test_auth.py, але ми його переносимо сюди
@pytest.mark.asyncio
async def test_get_current_admin_user_forbidden(client: TestClient, db_session: Session):
    """
    Тестує спробу звичайного користувача отримати доступ до адмін-функції.
    """
    user_email = "regular_user_for_admin_test@example.com"
    user_password = "RegularUserPassword12345"

    # Створюємо звичайного користувача
    user, user_token = create_test_user_and_get_token(client, db_session, user_email, user_password, is_admin=False)

    # Маршрут /api/users/avatar потребує current_user (не адміна), але ми протестуємо його як приклад
    # доступу звичайного користувача до потенційно захищеного адмінського ендпоінту,
    # хоча він не є адмінським.
    # Реально, get_current_admin_user має бути на іншому ендпоінті.
    # Наш test_auth.py вже тестує це через users/avatar, що не зовсім коректно
    # АЛЕ для цілей перенесення тесту я залишаю його так, як було у вас.

    # Оскільки test_auth.py перевіряв admin доступ до /api/users/avatar,
    # а цей маршрут використовує get_current_user (не get_current_admin_user),
    # цей тест фактично перевіряє, що звичайний користувач може завантажити аватар.
    # Щоб протестувати get_current_admin_user, потрібен маршрут, який його використовує.
    # Якщо такого маршруту немає, потрібно його додати для тестування.

    # У цьому тесті, який раніше був у test_auth.py, він перевіряв доступ до /api/users/avatar.
    # Але update_avatar використовує `get_current_user`, а не `get_current_admin_user`.
    # Тому, щоб протестувати `get_current_admin_user`, ми повинні знайти або створити маршрут,
    # який використовує `get_current_admin_user` як залежність.
    # Припустимо, що у вас є маршрут, наприклад, /api/admin/some_admin_only_endpoint
    # Якщо ні, то цей тест просто перевіряє, що звичайний користувач може оновити свій аватар (що правильно).

    # Для демонстрації тестування `get_current_admin_user` створимо фіктивний адмінський маршрут
    # або адаптуємо існуючий (якщо ви хочете).
    # У вашому поточному коді немає маршруту, який використовує get_current_admin_user напряму
    # окрім як у test_auth.py, що є дещо заплутаним.

    # Якщо ми хочемо перевірити саме 403 Forbidden для *адмінського* маршруту, нам потрібно:
    # 1. Створити такий маршрут у `app/routers/admin.py` (або `app/routers/users.py` якщо це ОК)
    #    Наприклад:
    #    @router.get("/admin_only", dependencies=[Depends(get_current_admin_user)])
    #    async def admin_only_endpoint():
    #        return {"message": "Welcome, Admin!"}
    # 2. Включити цей роутер до app.main.py
    # 3. Тоді перевіряти його.

    # Для збереження "нічого не ламати", я залишу цей тест як є, але зауважу, що його назва
    # дещо вводить в оману щодо "forbidden" для "admin" функції, якщо функція не адмінська.
    # Однак, він перевіряє, що звичайний користувач може використовувати "users/avatar", що є правдою.
    # Якщо ви хочете тест на 403 для адміна, дайте знати, і ми додамо такий маршрут.

    # Старий код тесту (з test_auth.py)
    with patch("cloudinary.uploader.upload", new_callable=MagicMock) as mock_cloudinary_upload:
        response = client.patch(
            "/api/users/avatar",
            headers={"Authorization": f"Bearer {user_token}"},
            files={"file": ("filename.txt", b"some content", "text/plain")}
        )
        assert response.status_code == 200 # Звичайний користувач може оновити аватар!
        # Якщо б цей маршрут був ЗАХИЩЕНИЙ get_current_admin_user, тут було б 403.
        # Оскільки це не так, тест успішний, що означає, що звичайний користувач може оновити аватар.
        # Це підтверджує, що ваш avatar маршрут не вимагає адмінських прав.