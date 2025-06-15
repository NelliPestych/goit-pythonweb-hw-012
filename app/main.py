"""
Головний файл застосунку Contacts App API.

Цей модуль ініціалізує FastAPI додаток, підключається до бази даних,
налаштовує маршрути, конфігурує CORS та реалізує обмеження швидкості запитів
за допомогою Redis.
"""

from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi_limiter import FastAPILimiter
from redis.asyncio import Redis
from dotenv import load_dotenv
import os
import time

from app.routers import contacts, auth_routes, users
from app.database import engine, Base, SessionLocal, create_db_and_tables
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.exc import OperationalError

load_dotenv()

app = FastAPI(title="Contacts API")

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

@app.on_event("startup")
async def startup():
    """
    Функція, що виконується під час запуску FastAPI застосунку.

    Ініціалізує з'єднання з Redis для використання FastAPILimiter.
    Змінні `REDIS_HOST` та `REDIS_PORT` зчитуються зі змінних середовища.
    Також намагається створити всі таблиці в базі даних, з повторними спробами.
    """
    redis_host = os.getenv("REDIS_HOST", "localhost")
    redis_port = int(os.getenv("REDIS_PORT", 6379))
    redis_client = Redis(host=redis_host, port=redis_port, db=0, encoding="utf-8", decode_responses=True)
    await FastAPILimiter.init(redis_client)

    max_retries = 15
    retry_delay = 5

    for i in range(max_retries):
        try:
            print(f"Attempt {i+1}/{max_retries}: Creating database tables...")
            create_db_and_tables()
            print("Database tables created successfully.")
            break
        except OperationalError as e:
            print(f"Database connection error: {e}. Retrying in {retry_delay} seconds...")
            time.sleep(retry_delay)
        except Exception as e:
            print(f"An unexpected error occurred during table creation: {e}")
            time.sleep(retry_delay)
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not connect to the database and create tables after multiple retries."
        )


@app.get("/")
def read_root():
    return {"message": "Welcome to the Contacts API!"}

app.include_router(contacts.router, prefix="/contacts", tags=["Contacts"])
app.include_router(auth_routes.router, prefix="/api", tags=["Auth"])
app.include_router(users.router, prefix="/api", tags=["Users"])
