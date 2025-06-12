from fastapi import FastAPI, Request, Depends
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi_limiter import FastAPILimiter
from redis.asyncio import Redis
from dotenv import load_dotenv
import os
from app.routers import contacts, auth, users
from app.database import engine, Base
from fastapi.middleware.cors import CORSMiddleware

Base.metadata.create_all(bind=engine)

load_dotenv()
app = FastAPI(title="Contacts API")

# CORS
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

# Rate Limiter
@app.on_event("startup")
async def startup():
    redis = Redis(host=os.getenv("REDIS_HOST", "localhost"), port=int(os.getenv("REDIS_PORT", 6379)), db=0, encoding="utf-8", decode_responses=True)
    await FastAPILimiter.init(redis)
app.include_router(contacts.router, prefix="/contacts", tags=["Contacts"])
app.include_router(auth.router, prefix="/api", tags=["Auth"])
app.include_router(users.router, prefix="/api", tags=["Users"])

