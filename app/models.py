"""
Tablas de la base de datos: Usuario, Sesion e IntentoFallido.
"""

import enum
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def _ahora_utc() -> datetime:
    return datetime.now(timezone.utc)


class RolUsuario(str, enum.Enum):
    """
    Hereda de `str` además de `Enum` para que Pydantic y `json.dumps` puedan serializar el
    valor directamente como texto ("usuario" / "administrador") sin pasos extra.
    """

    USUARIO = "usuario"
    ADMINISTRADOR = "administrador"


class Usuario(Base):
    __tablename__ = "usuarios"

    id: Mapped[int] = mapped_column(primary_key=True)
    nombre: Mapped[str] = mapped_column(String(120), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)

    # Los hashes de bcrypt tienen siempre 60 caracteres en su representación de texto
    # (formato "$2b$<costo>$<22 chars de salt><31 chars de hash>"); nunca se guarda la
    # contraseña en texto plano ni siquiera temporalmente en esta tabla.
    password_hash: Mapped[str] = mapped_column(String(60), nullable=False)

    rol: Mapped[RolUsuario] = mapped_column(
        SQLEnum(RolUsuario, name="rol_usuario"), default=RolUsuario.USUARIO, nullable=False
    )
    creado_en: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_ahora_utc)

    sesiones: Mapped[list["Sesion"]] = relationship(
        back_populates="usuario", cascade="all, delete-orphan"
    )


class Sesion(Base):
    """
    Representa una sesión de tipo cookie. No guardamos el token de sesión en texto plano acá:
    ver el comentario de `_hashear_token` en `core/sessions.py` para el motivo.
    """

    __tablename__ = "sesiones"

    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    usuario_id: Mapped[int] = mapped_column(ForeignKey("usuarios.id"), nullable=False)
    creado_en: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_ahora_utc)
    expira_en: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    usuario: Mapped["Usuario"] = relationship(back_populates="sesiones")


class IntentoFallido(Base):
    """
    Un registro por cada intento de login fallido. `core/rate_limit.py` cuenta cuántos
    registros recientes existen para un email y calcula el bloqueo progresivo a partir de eso,
    en vez de mantener un contador mutable en la tabla Usuario, para tener un historial
    auditable de intentos.
    """

    __tablename__ = "intentos_fallidos"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    creado_en: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_ahora_utc, index=True)
