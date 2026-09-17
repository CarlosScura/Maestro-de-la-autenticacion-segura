"""
Sesiones basadas en cookies: creación, verificación y eliminación.
"""

import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Response
from sqlalchemy.orm import Session

from app import models

MINUTOS_EXPIRACION_SESION = int(os.getenv("SESSION_EXPIRE_MINUTES", "60"))
NOMBRE_COOKIE_SESION = "session_id"

# Secure=True exige HTTPS (los navegadores tratan "localhost" como contexto seguro incluso
# por HTTP, así que esto no rompe el desarrollo local). Se puede desactivar con
# COOKIE_SECURE=false en .env únicamente para pruebas puntuales con curl sobre HTTP plano
# en una IP que no sea localhost; el requerimiento de seguridad pide Secure por defecto.
_COOKIE_SECURE = os.getenv("COOKIE_SECURE", "true").lower() == "true"


def _asegurar_utc(momento: datetime) -> datetime:
    # Postgres (TIMESTAMPTZ) devuelve datetimes con tzinfo; algunos backends usados en
    # pruebas locales (SQLite) los devuelven "naive" al releerlos de la base. Sin esto, la
    # comparación de más abajo puede tirar un TypeError según qué motor se esté usando.
    if momento.tzinfo is None:
        return momento.replace(tzinfo=timezone.utc)
    return momento


def _hashear_token(token: str) -> str:
    """
    Guardamos en la base el hash SHA-256 del token de sesión, no el token en texto plano.
    No es lo mismo que hashear una contraseña: el token ya tiene 256 bits de entropía
    aleatoria (no es algo que un atacante pueda adivinar por fuerza bruta ni por diccionario),
    así que no hace falta un algoritmo lento como bcrypt acá. Lo que buscamos es otra cosa:
    que si alguien accede de solo lectura a la base de datos (un backup filtrado, una
    inyección SQL de lectura, etc.) no pueda usar directamente esas filas como cookies
    válidas para suplantar sesiones activas.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def crear_sesion(db: Session, usuario: models.Usuario) -> str:
    """Crea una sesión nueva en la base y devuelve el token en texto plano (va a la cookie)."""
    token = secrets.token_urlsafe(32)
    expira_en = datetime.now(timezone.utc) + timedelta(minutes=MINUTOS_EXPIRACION_SESION)

    sesion = models.Sesion(
        token_hash=_hashear_token(token),
        usuario_id=usuario.id,
        expira_en=expira_en,
    )
    db.add(sesion)
    db.commit()
    return token


def verificar_sesion(db: Session, token: str) -> models.Usuario | None:
    """Busca la sesión por el hash del token recibido y devuelve el usuario si es válida."""
    sesion = (
        db.query(models.Sesion)
        .filter(models.Sesion.token_hash == _hashear_token(token))
        .first()
    )
    if sesion is None:
        return None

    if _asegurar_utc(sesion.expira_en) < datetime.now(timezone.utc):
        # Sesión vencida: la limpiamos de una vez en lugar de dejarla acumulada en la tabla.
        db.delete(sesion)
        db.commit()
        return None

    return sesion.usuario


def eliminar_sesion(db: Session, token: str) -> None:
    """Logout: borra la sesión de la base para que ese token deje de ser válido."""
    db.query(models.Sesion).filter(models.Sesion.token_hash == _hashear_token(token)).delete()
    db.commit()


def setear_cookie_sesion(response: Response, token: str) -> None:
    response.set_cookie(
        key=NOMBRE_COOKIE_SESION,
        value=token,
        httponly=True,  # inaccesible desde JavaScript: mitiga robo de la cookie vía XSS
        secure=_COOKIE_SECURE,  # nunca viaja por HTTP sin cifrar
        samesite="lax",  # no se envía en requests cross-site de terceros (mitiga CSRF básico),
        # pero sí en navegación normal del usuario (a diferencia de "strict")
        max_age=MINUTOS_EXPIRACION_SESION * 60,
        path="/",
    )


def borrar_cookie_sesion(response: Response) -> None:
    response.delete_cookie(key=NOMBRE_COOKIE_SESION, path="/")
