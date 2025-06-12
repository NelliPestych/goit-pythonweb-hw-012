FROM python:3.10-alpine

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

# Команда для запуску додатка (її можна перевизначити в docker-compose.yml)
# CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]