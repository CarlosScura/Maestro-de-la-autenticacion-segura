"""
Configuración compartida de los tests.

Todo lo que toca variables de entorno se hace ANTES de importar `app`: varios módulos de
`app/core/` y `app/database.py` leen `os.getenv(...)` en el momento en que se importan (ver
el docstring de `app/database.py`), así que setearlas después no tendría efecto.
"""

import os

from dotenv import load_dotenv
from sqlalchemy.engine import make_url

load_dotenv()


def _url_base_de_tests() -> str:
    """
    Por defecto se usa el mismo servidor y usuario de Postgres que en desarrollo, pero otra
    base (`passport_test_db`): así los tests no ensucian ni dependen de los datos de desarrollo
    y no hace falta configurar credenciales nuevas. Se puede pisar con TEST_DATABASE_URL.
    """
    url_explicita = os.getenv("TEST_DATABASE_URL")
    if url_explicita:
        return url_explicita
    url_dev = make_url(
        os.getenv(
            "DATABASE_URL",
            "postgresql+psycopg://passport_user:passport_pass@localhost:5432/passport_db",
        )
    )
    return url_dev.set(database="passport_test_db").render_as_string(hide_password=False)


_URL_TESTS = _url_base_de_tests()

# Red de seguridad: cada test borra y recrea todas las tablas, así que apuntar por error a la
# base de desarrollo la vaciaría.
if os.getenv("DATABASE_URL") and make_url(_URL_TESTS) == make_url(os.environ["DATABASE_URL"]):
    raise RuntimeError("TEST_DATABASE_URL no puede ser la misma base que DATABASE_URL")

os.environ["DATABASE_URL"] = _URL_TESTS

# TestClient habla con "http://testserver": no es HTTPS ni localhost, así que el cliente no
# reenviaría cookies marcadas como Secure y todos los tests de cookie fallarían.
os.environ["COOKIE_SECURE"] = "false"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import models  # noqa: E402
from app.database import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402

PASSWORD_VALIDA = "contraseña-segura-123"


@pytest.fixture(autouse=True)
def base_limpia():
    """Cada test arranca con las tablas vacías, sin depender del orden de ejecución."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture
def client():
    # Un cliente nuevo por test = un "navegador" nuevo, con su propio frasco de cookies.
    with TestClient(app) as cliente:
        yield cliente


@pytest.fixture
def registrar(client):
    """Registra un usuario por la API y devuelve sus datos de login."""

    def _registrar(email="ana@ejemplo.com", nombre="Ana", password=PASSWORD_VALIDA):
        respuesta = client.post(
            "/auth/registro", json={"nombre": nombre, "email": email, "password": password}
        )
        assert respuesta.status_code == 201, respuesta.text
        return {"email": email, "password": password}

    return _registrar


@pytest.fixture
def usuario(registrar):
    return registrar()


@pytest.fixture
def admin(registrar):
    """
    El registro público siempre crea rol `usuario` y no hay endpoint para promover, así que
    el administrador se crea igual que en el README: actualizando la fila en la base.
    """
    credenciales = registrar(email="admin@ejemplo.com", nombre="Admin")
    with SessionLocal() as db:
        fila = db.query(models.Usuario).filter_by(email=credenciales["email"]).one()
        fila.rol = models.RolUsuario.ADMINISTRADOR
        db.commit()
    return credenciales


def login(client, credenciales, metodo):
    return client.post("/auth/login", json={**credenciales, "metodo": metodo})


def headers_jwt(client, credenciales):
    respuesta = login(client, credenciales, "jwt")
    assert respuesta.status_code == 200, respuesta.text
    return {"Authorization": f"Bearer {respuesta.json()['access_token']}"}
