"""
Головний файл застосунку Contacts App API.

Цей модуль ініціалізує FastAPI додаток, підключається до бази даних,
налаштовує маршрути, конфігурує CORS та реалізує обмеження швидкості запитів
за допомогою Redis.
"""

from fastapi import FastAPI, Request, Depends
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi_limiter import FastAPILimiter
from redis.asyncio import Redis
from dotenv import load_dotenv
import os

from src.routers import contacts, auth_routes, users
from src.database import SessionLocal # SessionLocal все ще потрібен для залежностей
from fastapi.middleware.cors import CORSMiddleware


# Завантажуємо змінні середовища з файлу .env
load_dotenv()

# Ініціалізуємо FastAPI додаток
app = FastAPI(title="Contacts API")

# Конфігурація CORS (Cross-Origin Resource Sharing)
origins = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Конфігурація FastAPILimiter для обмеження швидкості запитів
@app.on_event("startup")
async def startup():
    """
    Функція, що виконується під час запуску FastAPI застосунку.

    Ініціалізує з'єднання з Redis для використання FastAPILimiter.
    Змінні `REDIS_HOST` та `REDIS_PORT` зчитуються зі змінних середовища.
    Створення таблиць бази даних тепер відбувається перед запуском Uvicorn
    через сервіс `db-init` у docker-compose.
    """
    if os.getenv("TESTING", "false").lower() == "true":
        print("Skipping Redis init during testing.")
        return

    redis_host = os.getenv("REDIS_HOST", "localhost")
    redis_port = int(os.getenv("REDIS_PORT", 6379))
    redis_client = Redis(host=redis_host, port=redis_port, db=0, encoding="utf-8", decode_responses=True)
    await FastAPILimiter.init(redis_client)
    print("FastAPILimiter initialized with Redis.")


# Додаємо простий кореневий маршрут для тестування
@app.get("/")
def read_root():
    """
    Корневий маршрут API.

    Повертає вітальне повідомлення.
    """
    return {"message": "Welcome to the Contacts API!"}


# Додаємо роутери
app.include_router(contacts.router, prefix="/api")
app.include_router(auth_routes.router, prefix="/api")
app.include_router(users.router, prefix="/api")