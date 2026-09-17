"""
Conexión a PostgreSQL con SQLAlchemy 2.0.

`load_dotenv()` se llama acá, apenas se importa este módulo, porque `app.main` importa
`app.routers.auth`, que a su vez importa `app.core.jwt_handler` y otros módulos de `core/`
que leen variables de entorno (claves secretas, cadena de conexión, etc.) en el momento en
que el módulo se carga, no en cada request. Si `load_dotenv()` se llamara más tarde, esos
módulos ya habrían leído `os.getenv(...)` sin encontrar los valores del archivo `.env`.
"""

import os

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

load_dotenv()

# Valor por defecto solo para que el proyecto arranque "out of the box" en desarrollo local;
# en cualquier entorno real esto se debe sobreescribir con una variable de entorno propia.
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg://passport_user:passport_pass@localhost:5432/passport_db",
)

# pool_pre_ping evita usar conexiones "muertas" del pool (por ejemplo, si Postgres se
# reinició y la conexión quedó colgada) devolviendo un error claro en vez de uno críptico.
engine = create_engine(DATABASE_URL, pool_pre_ping=True)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """Clase base declarativa de la que heredan todos los modelos (Usuario, Sesion, etc.)."""


def get_db():
    """
    Dependencia de FastAPI que entrega una sesión de base de datos por request y la cierra
    al final, incluso si la request termina con una excepción (por eso el try/finally).
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
