from typing import List, Optional
from pathlib import Path

from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType
from fastapi import BackgroundTasks, HTTPException, status
from pydantic import EmailStr

from dotenv import load_dotenv
import os

load_dotenv()

conf = ConnectionConfig(
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
    MAIL_FROM=os.getenv("MAIL_FROM"),
    # Налаштування для Meta.ua SMTP з SSL/TLS
    MAIL_PORT=int(os.getenv("MAIL_PORT", 465)), # Порт 465 для SSL
    MAIL_SERVER=os.getenv("MAIL_SERVER"),
    MAIL_FROM_NAME="Contacts App",
    MAIL_STARTTLS=False, # Вимикаємо STARTTLS
    MAIL_SSL_TLS=True,  # Вмикаємо явний SSL/TLS
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

    Args:
        email (EmailStr): Адреса електронної пошти одержувача.
        username (str): Ім'я користувача (зазвичай, також email).
        host (str): Базовий URL застосунку.
        token (str): Токен верифікації або скидання пароля.
        subject (Optional[str]): Тема електронного листа. За замовчуванням "Confirm your email for Contacts App".
    """
    try:
        message = MessageSchema(
            subject=subject,
            recipients=[email],
            template_body={"host": host, "username": username, "token": token},
            subtype=MessageType.html,
        )

        fm = FastMail(conf)
        await fm.send_message(message, template_name="email_verification.html")
        # Додаємо вивід посилання в термінал для налагодження
        # Це допоможе вам перевірити, чи правильно генеруються посилання
        print(f"DEBUG: Email sent to {email} with subject '{subject}' and link: {host}/api/auth/confirm_email/{token}")
    except Exception as e:
        print(f"Error sending email: {e}")
        # Якщо ви хочете, щоб API-виклик завершувався з помилкою 500,
        # якщо email не надіслано, то не використовуйте BackgroundTasks для send_email.
        # Але для цього сценарію це правильна поведінка.
        # raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error sending email: {e}")
