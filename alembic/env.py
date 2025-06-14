from logging.config import fileConfig
from sqlalchemy import engine_from_config
from sqlalchemy import pool
from alembic import context
import os
from dotenv import load_dotenv

# Завантажуємо змінні середовища, щоб Alembic міг їх використовувати,
# особливо для підключення до БД, якщо DATABASE_URL залежить від .env
load_dotenv()

# !!! ВАЖЛИВО: Імпортуємо Base та моделі тут, щоб Alembic міг їх "побачити" !!!
# Переконайтеся, що шлях до app.database та app.models є коректним
from app.database import Base
from app import models # Це гарантує, що всі ваші моделі (User, Contact)
                        # будуть зареєстровані з Base.metadata

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
target_metadata = Base.metadata # !!! ТУТ ЗМІНИ НЕМАЄ, ЦЕ ВЖЕ БУЛО КОРЕКТНО.
                               # Просто переконуємося, що Base.metadata доступний.

# Інші значення з конфігурації, визначені потребами env.py,
# можуть бути отримані:
# my_important_option = config.get_main_option("my_important_option")
# ... тощо.

def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


# Ця функція гарантує, що моделі завантажені
# Вона повинна викликатися перед тим, як Alembic перевірятиме metadata
def ensure_models_loaded():
    # Просто імпортуємо моделі, щоб Base.metadata був оновлений
    # Цей блок буде виконано під час запуску Alembic
    pass # Моделі вже імпортовані на початку файлу, цього достатньо

if context.is_offline_mode():
    run_migrations_offline()
else:
    # Забезпечуємо завантаження моделей перед запуском онлайн-міграцій
    ensure_models_loaded()
    run_migrations_online()