# app/email.py
"""
Модуль для надсилання електронних листів.
Використовує FastAPI-Mail для конфігурації SMTP та шаблонів.
"""

from typing import Optional
from pathlib import Path

from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType
from fastapi import HTTPException, status, Request # Import Request from fastapi
from pydantic import EmailStr

from dotenv import load_dotenv
import os

load_dotenv()

conf = ConnectionConfig(
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
    MAIL_FROM=os.getenv("MAIL_FROM"),
    MAIL_PORT=int(os.getenv("MAIL_PORT", 465)),
    MAIL_SERVER=os.getenv("MAIL_SERVER"),
    MAIL_FROM_NAME="Contacts App",
    MAIL_STARTTLS=False, # Changed to False for better compatibility with some SMTPs, or based on your setup
    MAIL_SSL_TLS=True,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True,
    TEMPLATE_FOLDER=Path(__file__).parent / 'templates',
)

async def send_email(
    email_to: EmailStr,     # Email одержувача
    username: str,          # Ім'я користувача для шаблону
    token: str,             # Токен для підтвердження/скидання
    request: Request,       # Об'єкт запиту для генерації URL
    reset_password: bool = False # Прапорець для визначення типу листа
):
    """
    Відправляє email з підтвердженням або скиданням пароля.

    Args:
        email_to (EmailStr): email одержувача.
        username (str): Ім'я користувача для використання в шаблоні листа.
        token (str): Токен для підтвердження email або скидання пароля.
        request (Request): Об'єкт запиту FastAPI для побудови URL.
        reset_password (bool): True, якщо це лист для скидання пароля, False для підтвердження.
    """
    try:
        # Визначаємо тему та назву шаблону в залежності від типу листа
        if reset_password:
            subject = "Password Reset Request for Contacts App"
            # Для скидання пароля посилання йде на /api/auth/reset_password/{token}
            # url_for приймає 'name' роуту, яке за замовчуванням є назвою функції
            link = request.url_for("reset_password", token=token)
            template_name = "password_reset.html" # Припускаємо, що у вас є цей шаблон
        else:
            subject = "Confirm your email for Contacts App"
            # Для підтвердження email посилання йде на /api/auth/confirm_email/{token}
            link = request.url_for("confirm_email", token=token)
            template_name = "email_verification.html" # Припускаємо, що у вас є цей шаблон

        # Дані, які будуть передані в шаблон листа
        email_data = {
            "username": username,
            "link": str(link) # Перетворюємо URL в рядок для шаблону
        }

        message = MessageSchema(
            subject=subject,
            recipients=[email_to],
            template_body=email_data, # Передаємо словник з даними для шаблону
            subtype=MessageType.html,
        )

        fm = FastMail(conf)
        await fm.send_message(message, template_name=template_name)

        # Додаємо вивід посилання в термінал для налагодження
        print(f"DEBUG: Email sent to {email_to} with link: {link} (Subject: {subject})")

    except Exception as e:
        # Логуємо помилку відправки email, але не підвищуємо HTTPException,
        # оскільки це фонова задача, і основний HTTP-запит вже може бути завершений.
        print(f"ERROR: Failed to send email to {email_to}. Details: {e}")
        # Якщо ви хочете, щоб API-виклик завершувався з помилкою 500,
        # якщо email не надіслано, то не використовуйте BackgroundTasks для send_email.
        # Але для цього сценарію це правильна поведінка.
