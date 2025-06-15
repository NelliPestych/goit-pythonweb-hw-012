"""
Модуль для інтеграційних тестів основних маршрутів застосунку.
"""

def test_read_main(client):
    """
    Тестує кореневий маршрут '/' застосунку.

    Перевіряє, чи повертає маршрут очікуване повідомлення "Welcome to the Contacts API!".
    """
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Welcome to the Contacts API!"}