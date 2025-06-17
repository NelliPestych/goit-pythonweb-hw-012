FROM python:3.10-alpine

WORKDIR /app

RUN apk update && apk add --no-cache \
    postgresql-client \
    dos2unix \
    build-base \
    libffi-dev \
    && rm -rf /var/cache/apk/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ./wait_for_db.sh ./wait_for_db.sh
RUN dos2unix ./wait_for_db.sh
RUN chmod +x ./wait_for_db.sh

COPY . .

EXPOSE 8000

CMD ["sh", "-c", "./wait_for_db.sh && uvicorn src.main:app --host 0.0.0.0 --port 8000"]