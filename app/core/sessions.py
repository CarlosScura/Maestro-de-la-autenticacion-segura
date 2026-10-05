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

# Secure=True exige HTTPS.
_COOKIE_SECURE = os.getenv("COOKIE_SECURE", "true").lower() == "true"


def _asegurar_utc(momento: datetime) -> datetime:
    # Postgres (TIMESTAMPTZ) devuelve datetimes con tzinfo; algunos backends usados en
    # pruebas locales (SQLite) los devuelven "naive" al releerlos de la base.
    if momento.tzinfo is None:
        return momento.replace(tzinfo=timezone.utc)
    return momento


def _hashear_token(token: str) -> str:
    """
    Guardamos en la base el hash SHA-256 del token de sesión.
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
        httponly=True,  # inaccesible desde JavaScript
        secure=_COOKIE_SECURE,  # nunca viaja por HTTP sin cifrar
        samesite="lax",  # no se envía en requests cross-site de terceros
        max_age=MINUTOS_EXPIRACION_SESION * 60,
        path="/",
    )


def borrar_cookie_sesion(response: Response) -> None:
    response.delete_cookie(key=NOMBRE_COOKIE_SESION, path="/")
