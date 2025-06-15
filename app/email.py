from typing import List, Optional
from pathlib import Path

from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType # Розкоментовано імпорти
from fastapi import BackgroundTasks, HTTPException, status
from pydantic import EmailStr

from dotenv import load_dotenv
import os

load_dotenv()

# Конфігурація FastMail знову активована
conf = ConnectionConfig(
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
    MAIL_FROM=os.getenv("MAIL_FROM"),
    MAIL_PORT=int(os.getenv("MAIL_PORT", 465)), # Використовуємо 465 як порт за замовчуванням
    MAIL_SERVER=os.getenv("MAIL_SERVER"),
    MAIL_FROM_NAME="Contacts App",
    MAIL_STARTTLS=False,
    MAIL_SSL_TLS=True,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True,
    TEMPLATE_FOLDER=Path(__file__).parent / 'templates',
)

async def send_email(
    email: EmailStr,
    username: str,
    host: str,
    token: str,
    subject: Optional[str] = "Confirm your email for Contacts App"
):
    """
    Відправляє електронний лист для підтвердження email або скидання пароля.
    Виводить посилання в логи перед відправкою листа.

    Args:
        email (EmailStr): Адреса електронної пошти одержувача.
        username (str): Ім'я користувача (зазвичай, також email).
        host (str): Базовий URL застосунку.
        token (str): Токен верифікації або скидання пароля.
        subject (Optional[str]): Тема електронного листа. За замовчуванням "Confirm your email for Contacts App".
    """
    # Завжди виводимо посилання в лог
    if subject == "Password Reset Request":
        print(f"DEBUG: Password Reset Email link for {email}: {host}/api/auth/reset_password/{token}")
    else:
        print(f"DEBUG: Email confirmation link for {email}: {host}/api/auth/confirm_email/{token}")

    # Тепер намагаємося відправити реальний лист
    try:
        message = MessageSchema(
            subject=subject,
            recipients=[email],
            template_body={"host": host, "username": username, "token": token},
            subtype=MessageType.html,
        )

        fm = FastMail(conf)
        await fm.send_message(message, template_name="email_verification.html")
        print(f"INFO: Successfully attempted to send email to {email} with subject '{subject}'.") # Додано для підтвердження успішної спроби

    except Exception as e:
        print(f"ERROR: Failed to send email to {email} with subject '{subject}': {e}") # Більш детальне повідомлення про помилку
        # Продовжуємо викидати виняток, щоб API повернув 500, якщо відправка не вдалася
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error sending email: {e}")
