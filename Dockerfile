FROM python:3.10-alpine

WORKDIR /app

# Встановлюємо необхідні залежності та утиліти для Alpine
# Включаємо make, postgresql-client, dos2unix, build-base, libffi-dev
RUN apk update && apk add --no-cache \
    make \
    postgresql-client \
    dos2unix \
    build-base \
    libffi-dev \
    && rm -rf /var/cache/apk/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копіюємо скрипт очікування бази даних до робочої директорії /app
COPY ./wait_for_db.sh /app/wait_for_db.sh

# Виправляємо кінці рядків скрипта
RUN dos2unix /app/wait_for_db.sh

# Робимо скрипт виконуваним
RUN chmod +x /app/wait_for_db.sh

# Копіюємо весь код застосунку
COPY . .

EXPOSE 8000

# Команда запуску застосунку буде перевизначена в docker-compose.yml
# CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
