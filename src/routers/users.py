"""
Модуль для управління операціями, пов'язаними з користувачами,
такими як оновлення аватара та отримання інформації про поточного користувача.
"""

from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, status
from sqlalchemy.orm import Session
from src import deps, crud, models, schemas
from src.auth import get_current_user, get_current_admin_user
import cloudinary
import cloudinary.uploader
from dotenv import load_dotenv
import os
from typing import Optional

load_dotenv()

router = APIRouter(prefix="/users", tags=["Users"])

CLOUDINARY_CLOUD_NAME = os.getenv("CLOUDINARY_CLOUD_NAME")
CLOUDINARY_API_KEY = os.getenv("CLOUDINARY_API_KEY")
CLOUDINARY_API_SECRET = os.getenv("CLOUDINARY_API_SECRET")

try:
    cloudinary.config(
        cloud_name=CLOUDINARY_CLOUD_NAME,
        api_key=CLOUDINARY_API_KEY,
        api_secret=CLOUDINARY_API_SECRET,
    )
    print("Cloudinary configuration successful (or at least no immediate error).")
except Exception as e:
    print(f"Error configuring Cloudinary: {e}")

@router.get("/current_user", response_model=schemas.UserOut)
async def read_users_me(current_user: models.User = Depends(get_current_user)):
    """
    Отримує інформацію про поточного аутентифікованого користувача.

    Args:
        current_user (models.User): Поточний аутентифікований користувач, отриманий з токена.

    Returns:
        schemas.UserOut: Схема даних поточного користувача.
    """
    return current_user


@router.patch("/avatar", response_model=schemas.UserOut)
async def update_avatar(
    file: Optional[UploadFile] = File(None),
    current_user: models.User = Depends(get_current_admin_user),
    db: Session = Depends(deps.get_db)
):
    """
    Оновлює аватар поточного користувача.

    Ця операція доступна лише адміністраторам.

    Завантажує зображення на Cloudinary та зберігає URL аватара в базі даних користувача.

    Args:
        file (UploadFile): Файл зображення для завантаження.
        current_user (models.User): Поточний аутентифікований користувач (гарантовано адміністратор).
        db (Session): Сесія бази даних.

    Raises:
        HTTPException:
            - 422 UNPROCESSABLE_ENTITY: Якщо файл аватара не надано.
            - 403 FORBIDDEN: Якщо користувач не є адміністратором (обробляється залежністю).
            - 404 NOT_FOUND: Якщо користувача не знайдено в базі даних.
            - 500 INTERNAL_SERVER_ERROR: Якщо сталася помилка під час завантаження на Cloudinary
                                         або інша внутрішня помилка сервера.

    Returns:
        schemas.UserOut: Оновлений об'єкт користувача з новим URL аватара.
    """
    if not file:
        raise HTTPException(status_code=422, detail="Avatar file is required.")

    print(f"Attempting to upload avatar for user ID: {current_user.id}")
    try:
        r = cloudinary.uploader.upload(file.file, folder="avatars", public_id=f"avatar_{current_user.id}", overwrite=True)
        avatar_url = r.get("secure_url")
        print(f"Cloudinary upload result: {r}")
        print(f"New avatar URL: {avatar_url}")

        user = crud.get_user_by_email(db, email=current_user.email)
        if user:
            user.avatar_url = avatar_url
            db.commit()
            db.refresh(user)
            return user
        raise HTTPException(status_code=404, detail="User not found")
    except cloudinary.exceptions.Error as ce:
        print(f"Cloudinary API Error: {ce}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Cloudinary upload failed: {ce}")
    except Exception as e:
        print(f"An unexpected error occurred during avatar upload: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Internal server error: {e}")

@router.patch("/admin_only")
async def admin_only_endpoint(current_user: models.User = Depends(get_current_admin_user)):
    """
    Приклад ендпоінту, доступного лише адміністраторам.

    Args:
        current_user (models.User): Поточний аутентифікований користувач (гарантовано адміністратор).

    Returns:
        dict: Повідомлення про успішний доступ.
    """
    return {"message": "You are an admin"}