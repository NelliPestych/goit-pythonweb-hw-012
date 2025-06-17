# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------
# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
import os
import sys
# ВИПРАВЛЕНО: Додаємо корінь проекту до Python Path
# Якщо conf.py знаходиться в docs/source/, то нам потрібно піднятися на два рівні вгору,
# щоб потрапити до кореня проекту, де знаходиться папка src/.
sys.path.insert(0, os.path.abspath('../..')) # Правильний шлях для docs/source/conf.py

# -- Project information -----------------------------------------------------\
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'Contacts App API'
copyright = '2025, NelliPestych'
author = 'NelliPestych'
release = '0.1.0'

# -- General configuration ---------------------------------------------------\
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    'sphinx.ext.autodoc',             # Для автоматичної генерації документації з docstrings
    'sphinx.ext.napoleon',            # Для підтримки Google та NumPy стилів docstrings
    'sphinx_rtd_theme',               # Тема "Read the Docs" для документації
    'sphinx_autodoc_typehints',       # Для правильного відображення типів з анотацій Python
    'sphinx.ext.todo',                # Можна додати для підтримки TODO-нотаток в документації
    'sphinx.ext.viewcode',            # Додає посилання на вихідний код у документації
]

# ОБОВ'ЯЗКОВО: Додано autodoc_mock_imports для залежностей
autodoc_mock_imports = [
    "fastapi",
    "sqlalchemy",
    "pydantic",
    "jose",
    "passlib",
    "fastapi_mail",
    "redis",
    "cloudinary",
    "dotenv",
    "alembic"
]

templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store'] # Ігнорувати ці файли та папки при збірці


# -- Options for HTML output -------------------------------------------------\
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'sphinx_rtd_theme' # Встановлюємо тему "Read the Docs"
html_static_path = ['_static']

# Якщо ви використовуєте Markdown для деяких файлів, розкоментуйте
# source_suffix = {
#     '.rst': 'restructuredtext',
#     '.md': 'markdown',
# }