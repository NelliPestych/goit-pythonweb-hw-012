
# 📇 FastAPI Contacts Application

Це RESTful API-застосунок для керування контактами користувача з підтримкою:
- Реєстрації, логіну та підтвердження email
- Завантаження аватарів через Cloudinary
- Пошуку, фільтрації й сортування контактів
- Кешування з Redis
- Документації через Sphinx
- Автентифікації з JWT
- Асинхронної обробки email

---

## ⚙️ Встановлення

### 1. Клонування репозиторію

```bash
git clone https://github.com/NelliPestych/goit-pythonweb-hw-012.git
cd goit-pythonweb-hw-012
```

### 2. Віртуальне середовище та залежності

```bash
python -m venv venv
source venv/bin/activate  # або `venv\Scripts\activate` на Windows

pip install --upgrade pip
pip install -r requirements.txt
```

> ✅ У проєкті використовується FastAPI, SQLAlchemy, Alembic, Redis, Cloudinary, Pydantic, EmailValidator тощо.

---

## 🐳 Запуск із Docker (рекомендовано)

```bash
docker-compose up --build
```

Це підніме:
- FastAPI-сервер
- PostgreSQL
- Redis

---

## 🧪 Запуск тестів
у файлі .env обовязково поставити залежність TESTING=true
```bash
pytest --disable-warnings
```

### Використовується:
- SQLite як тестова база
- Redis замоканий через MagicMock
- Повна ізоляція тестового середовища (див. `conftest.py`)

---

## 📄 Документація Sphinx

```bash
cd docs
make html
open _build/html/index.html  # або просто відкрий HTML у браузері
```

---

## 📁 .env

```env
DATABASE_URL="postgresql://postgres:postgres@db:5432/contacts_db"
SECRET_KEY="my_super_secret_key_here_for_jwt"
ALGORITHM="HS256"
ACCESS_TOKEN_EXPIRE_MINUTES=30
EMAIL_VERIFICATION_TOKEN_EXPIRE_MINUTES=1440
MAIL_USERNAME="nellip@meta.ua"
MAIL_PASSWORD="QwertyU1/2/3/"
MAIL_FROM="nellip@meta.ua"
MAIL_PORT=465
MAIL_SERVER="smtp.meta.ua"
MAIL_STARTTLS=False
MAIL_SSL_TLS=True
USE_CREDENTIALS=True
CLOUDINARY_CLOUD_NAME="dq4qdzogr"
CLOUDINARY_API_KEY="521687467524443"
CLOUDINARY_API_SECRET="pjgXuaM1WJwRGbQZmr2zYy6-GKg"
USER_CACHE_EXPIRE_MINUTES=60
POSTGRES_DB=contacts_db
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
PASSWORD_RESET_TOKEN_EXPIRE_MINUTES=60
REDIS_HOST=redis
REDIS_PORT=6379
TESTING=false
```

---

## 📚 Автор

- ✍️ Студентка GoIT: Nelli Pestych
