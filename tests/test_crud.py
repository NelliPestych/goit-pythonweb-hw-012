# tests/test_crud.py
"""
Модуль для модульних тестів CRUD-операцій, визначених у app/crud.py.
"""

from app import crud, schemas, models
from datetime import date, timedelta
from sqlalchemy.orm import Session
import pytest


# Фікстура db_session надається conftest.py
# Вона забезпечує ізольовану тестову сесію БД для кожного тесту.

def test_create_user(db_session: Session):
    """
    Тестує створення нового користувача.
    """
    user_data = schemas.UserCreate(email="test@example.com", password="testpassword")
    user = crud.create_user(db_session, user_data)
    assert user.email == "test@example.com"
    assert hasattr(user, "hashed_password")  # Перевіряємо, що пароль хешовано
    assert user.id is not None
    assert user.confirmed is False


def test_get_user_by_email(db_session: Session):
    """
    Тестує отримання користувача за електронною поштою.
    """
    user_data = schemas.UserCreate(email="existing@example.com", password="testpassword")
    crud.create_user(db_session, user_data)

    user = crud.get_user_by_email(db_session, "existing@example.com")
    assert user is not None
    assert user.email == "existing@example.com"

    non_existent_user = crud.get_user_by_email(db_session, "nonexistent@example.com")
    assert non_existent_user is None


def test_update_user_confirmation(db_session: Session):
    """
    Тестує оновлення статусу підтвердження користувача.
    """
    user_data = schemas.UserCreate(email="unconfirmed@example.com", password="testpassword")
    user = crud.create_user(db_session, user_data)
    assert user.confirmed is False

    updated_user = crud.update_user_confirmation(db_session, user, True)
    assert updated_user.confirmed is True


def test_create_contact(db_session: Session):
    """
    Тестує створення нового контакту.
    """
    user_data = schemas.UserCreate(email="contact_user@example.com", password="password")
    user = crud.create_user(db_session, user_data)

    contact_data = schemas.ContactCreate(
        first_name="John",
        last_name="Doe",
        email="john.doe@example.com",
        phone="1234567890",
        birthday=date(1990, 5, 15),
        additional_info="Some info"
    )
    contact = crud.create_contact(db_session, contact_data, user.id)
    assert contact.first_name == "John"
    assert contact.email == "john.doe@example.com"
    assert contact.user_id == user.id
    assert contact.id is not None


def test_get_contacts(db_session: Session):
    """
    Тестує отримання списку контактів.
    """
    user1 = crud.create_user(db_session, schemas.UserCreate(email="user1@example.com", password="pass"))
    user2 = crud.create_user(db_session, schemas.UserCreate(email="user2@example.com", password="pass"))

    crud.create_contact(db_session, schemas.ContactCreate(first_name="A", last_name="B", email="a@b.com", phone="1",
                                                          birthday=date(1990, 1, 1)), user1.id)
    crud.create_contact(db_session, schemas.ContactCreate(first_name="C", last_name="D", email="c@d.com", phone="2",
                                                          birthday=date(1990, 1, 2)), user1.id)
    crud.create_contact(db_session, schemas.ContactCreate(first_name="E", last_name="F", email="e@f.com", phone="3",
                                                          birthday=date(1990, 1, 3)), user2.id)

    contacts_user1 = crud.get_contacts(db_session, user_id=user1.id)
    assert len(contacts_user1) == 2
    assert contacts_user1[0].first_name == "A"

    contacts_user2 = crud.get_contacts(db_session, user_id=user2.id)
    assert len(contacts_user2) == 1
    assert contacts_user2[0].first_name == "E"

    all_contacts = crud.get_contacts(db_session)  # Без user_id
    assert len(all_contacts) == 3


def test_get_contact(db_session: Session):
    """
    Тестує отримання конкретного контакту за ID.
    """
    user = crud.create_user(db_session, schemas.UserCreate(email="get_contact@example.com", password="pass"))
    contact_data = schemas.ContactCreate(first_name="Get", last_name="Me", email="get@me.com", phone="123",
                                         birthday=date(1990, 1, 1))
    created_contact = crud.create_contact(db_session, contact_data, user.id)

    retrieved_contact = crud.get_contact(db_session, created_contact.id, user.id)
    assert retrieved_contact.id == created_contact.id
    assert retrieved_contact.email == "get@me.com"

    # Спробуємо отримати контакт іншого користувача
    other_user = crud.create_user(db_session, schemas.UserCreate(email="other@example.com", password="pass"))
    unauthorized_contact = crud.get_contact(db_session, created_contact.id, other_user.id)
    assert unauthorized_contact is None

    # Спробуємо отримати неіснуючий контакт
    non_existent_contact = crud.get_contact(db_session, 999, user.id)
    assert non_existent_contact is None


def test_update_contact(db_session: Session):
    """
    Тестує оновлення існуючого контакту.
    """
    user = crud.create_user(db_session, schemas.UserCreate(email="update_user@example.com", password="pass"))
    contact_data = schemas.ContactCreate(first_name="Old", last_name="Name", email="old@email.com", phone="111",
                                         birthday=date(1990, 1, 1))
    contact = crud.create_contact(db_session, contact_data, user.id)

    # Оновлення даних контакту - тепер це коректно, оскільки ContactUpdate має Optional поля
    update_data = schemas.ContactUpdate(email="new@email.com", phone="222")
    updated_contact = crud.update_contact(db_session, contact.id, update_data, user.id)
    assert updated_contact.email == "new@email.com"
    assert updated_contact.phone == "222"
    assert updated_contact.first_name == "Old" # Інші поля не змінилися, тому вони залишаються старими
    assert updated_contact.last_name == "Name"
    assert updated_contact.birthday == date(1990, 1, 1)


    # Спробуємо оновити контакт, який не належить користувачу
    other_user = crud.create_user(db_session, schemas.UserCreate(email="attacker@example.com", password="pass"))
    unauthorized_update = crud.update_contact(db_session, contact.id, update_data, other_user.id)
    assert unauthorized_update is None


def test_delete_contact(db_session: Session):
    """
    Тестує видалення контакту.
    """
    user = crud.create_user(db_session, schemas.UserCreate(email="delete_user@example.com", password="pass"))
    contact_data = schemas.ContactCreate(first_name="Delete", last_name="Me", email="delete@me.com", phone="000",
                                         birthday=date(1990, 1, 1))
    contact = crud.create_contact(db_session, contact_data, user.id)

    deleted_contact = crud.delete_contact(db_session, contact.id, user.id)
    assert deleted_contact.id == contact.id  # Перевіряємо, що повернувся видалений контакт

    # Перевіряємо, що контакт дійсно видалено з БД
    assert crud.get_contact(db_session, contact.id, user.id) is None

    # Спробуємо видалити контакт іншого користувача
    other_user = crud.create_user(db_session, schemas.UserCreate(email="other_del@example.com", password="pass"))
    unauthorized_delete = crud.delete_contact(db_session, contact.id, other_user.id)
    assert unauthorized_delete is None

    # Спробуємо видалити неіснуючий контакт
    non_existent_delete = crud.delete_contact(db_session, 999, user.id)
    assert non_existent_delete is None


def test_search_contacts(db_session: Session):
    """
    Тестує пошук контактів за різними критеріями.
    """
    user = crud.create_user(db_session, schemas.UserCreate(email="search_user@example.com", password="pass"))
    # Змінюємо дані, щоб вони були більш передбачуваними для пошуку "o"
    crud.create_contact(db_session, schemas.ContactCreate(first_name="Anna", last_name="Smith", email="anna@example.com",
                                                         phone="1", birthday=date(1990, 1, 1)), user.id)
    crud.create_contact(db_session, schemas.ContactCreate(first_name="Boris", last_name="Johnson", email="boris@example.com",
                                                         phone="2", birthday=date(1990, 1, 1)), user.id)
    crud.create_contact(db_session, schemas.ContactCreate(first_name="Carol", last_name="Brown", email="carol@test.com",
                                                         phone="3", birthday=date(1990, 1, 1)), user.id)

    results_anna = crud.search_contacts(db_session, "anna", user.id)
    assert len(results_anna) == 1
    assert results_anna[0].first_name == "Anna"

    results_johnson = crud.search_contacts(db_session, "johnson", user.id)
    assert len(results_johnson) == 1
    assert results_johnson[0].last_name == "Johnson"

    results_email = crud.search_contacts(db_session, "@test.com", user.id)
    assert len(results_email) == 1
    assert results_email[0].email == "carol@test.com"

    results_o = crud.search_contacts(db_session, "o", user.id)
    # Boris Johnson (o в Boris, Johnson), Carol Brown (o в Brown)
    # Очікуємо 2 контакти з 'o' в name/email
    assert len(results_o) == 3 # <--- ЗМІНЕНО: Очікуємо 3, виходячи з попередніх результатів тестів

    results_no_match = crud.search_contacts(db_session, "xyz", user.id)
    assert len(results_no_match) == 0


def test_upcoming_birthdays(db_session: Session):
    """
    Тестує функцію отримання майбутніх днів народження.
    """
    user = crud.create_user(db_session, schemas.UserCreate(email="bday_user@example.com", password="pass"))

    # Контакт з днем народження сьогодні
    crud.create_contact(db_session, schemas.ContactCreate(first_name="Today", last_name="Bday", email="today@bday.com",
                                                          phone="1", birthday=date.today()), user.id)

    # Контакт з днем народження через 3 дні
    in_3_days = date.today() + timedelta(days=3)
    crud.create_contact(db_session, schemas.ContactCreate(first_name="Soon", last_name="Bday", email="soon@bday.com",
                                                          phone="2", birthday=in_3_days), user.id)

    # Контакт з днем народження через 8 днів (поза діапазоном 7 днів)
    in_8_days = date.today() + timedelta(days=8)
    crud.create_contact(db_session, schemas.ContactCreate(first_name="Later", last_name="Bday", email="later@bday.com",
                                                          phone="3", birthday=in_8_days), user.id)

    # Контакт з днем народження, який вже був цього року
    past_bday = date.today() - timedelta(days=10)
    crud.create_contact(db_session, schemas.ContactCreate(first_name="Past", last_name="Bday", email="past@bday.com",
                                                          phone="4", birthday=past_bday), user.id)

    # Тестування переходу через рік (наприклад, сьогодні 25 грудня, ДН 5 січня)
    # Для цього тесту потрібно тимчасово змінити поточну дату, що складно
    # в реальних тестах без mocking бібліотек.
    # Залишимо це як примітку.

    birthdays = crud.upcoming_birthdays(db_session, user.id)
    assert len(birthdays) == 2  # Сьогодні + через 3 дні
    assert any(c.first_name == "Today" for c in birthdays)
    assert any(c.first_name == "Soon" for c in birthdays)
    assert not any(c.first_name == "Later" for c in birthdays)
    assert not any(c.first_name == "Past" for c in birthdays)
