"""Shared extension singletons (kept separate to avoid circular imports)."""
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
