"""
Bloqueo progresivo tras intentos fallidos de login.

Un bloqueo fijo (ej: "3 intentos y bloqueado 5 minutos siempre") es fácil de eludir con
paciencia; un bloqueo progresivo hace cada vez más costoso seguir probando contraseñas,
sin bloquear permanentemente a un usuario legítimo que se equivocó un par de veces.
"""

from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app import models

_UMBRALES_DE_BLOQUEO: list[tuple[int, timedelta]] = [
    (3, timedelta(seconds=30)),
    (5, timedelta(minutes=2)),
    (7, timedelta(minutes=10)),
    (10, timedelta(minutes=30)),
]

_VENTANA_DE_CONTEO = timedelta(hours=1)


def _asegurar_utc(momento: datetime) -> datetime:
    # Mismo motivo que en core/sessions.py: algunos backends (SQLite en pruebas locales)
    # devuelven datetimes "naive" al releerlos, aunque Postgres los devuelva con tzinfo.
    if momento.tzinfo is None:
        return momento.replace(tzinfo=timezone.utc)
    return momento


def _duracion_bloqueo_para(cantidad_de_fallos: int) -> timedelta | None:
    duracion = None
    for umbral, espera in _UMBRALES_DE_BLOQUEO:
        if cantidad_de_fallos >= umbral:
            duracion = espera
    return duracion


def verificar_bloqueo(db: Session, email: str) -> None:
    """
    Se llama ANTES de intentar validar la contraseña. Si el email está bloqueado por
    demasiados fallos recientes, corta acá con 429 y no llega ni a consultar el hash.
    """
    desde = datetime.now(timezone.utc) - _VENTANA_DE_CONTEO
    intentos_recientes = (
        db.query(models.IntentoFallido)
        .filter(models.IntentoFallido.email == email, models.IntentoFallido.creado_en >= desde)
        .order_by(models.IntentoFallido.creado_en.desc())
        .all()
    )
    if not intentos_recientes:
        return

    duracion = _duracion_bloqueo_para(len(intentos_recientes))
    if duracion is None:
        return

    desbloqueo_en = _asegurar_utc(intentos_recientes[0].creado_en) + duracion
    ahora = datetime.now(timezone.utc)
    if ahora < desbloqueo_en:
        segundos_restantes = int((desbloqueo_en - ahora).total_seconds())
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Demasiados intentos fallidos. Probá de nuevo en {segundos_restantes} segundos.",
            headers={"Retry-After": str(segundos_restantes)},
        )


def registrar_intento_fallido(db: Session, email: str, ip_address: str | None = None) -> None:
    db.add(models.IntentoFallido(email=email, ip_address=ip_address))
    db.commit()


def limpiar_intentos_fallidos(db: Session, email: str) -> None:
    """Se llama tras un login exitoso: un login correcto resetea el contador de fallos."""
    db.query(models.IntentoFallido).filter(models.IntentoFallido.email == email).delete()
    db.commit()
