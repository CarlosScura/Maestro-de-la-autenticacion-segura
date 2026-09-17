"""
Modelos Pydantic v2 de request/response.
"""

import html
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.models import RolUsuario


def _sanitizar_texto_libre(valor: str) -> str:
    """
    Escapa caracteres especiales de HTML (<, >, &, comillas) en campos de texto libre que
    ingresa el usuario (por ejemplo, el nombre). No confiamos en que quien consuma esta API
    vaya a escapar el dato antes de renderizarlo en una página HTML más adelante: sanitizamos
    en el borde de entrada para que un nombre como "<script>alert(1)</script>" nunca llegue
    a la base de datos con su forma ejecutable, sin importar dónde se muestre después.
    """
    return html.escape(valor.strip())


class UsuarioRegistro(BaseModel):
    nombre: str = Field(min_length=1, max_length=120)
    email: EmailStr
    password: str = Field(min_length=8)

    @field_validator("nombre")
    @classmethod
    def _sanear_nombre(cls, v: str) -> str:
        return _sanitizar_texto_libre(v)

    @field_validator("email")
    @classmethod
    def _normalizar_email(cls, v: str) -> str:
        # Normalizamos a minúsculas para que "Ana@Mail.com" y "ana@mail.com" no puedan
        # registrarse como dos cuentas distintas.
        return v.lower()

    @field_validator("password")
    @classmethod
    def _validar_longitud_para_bcrypt(cls, v: str) -> str:
        # bcrypt solo procesa los primeros 72 bytes de la contraseña; si se la dejara pasar
        # más larga, la librería la truncaría en silencio y dos contraseñas distintas que
        # compartan esos primeros 72 bytes generarían el mismo hash. Preferimos rechazar
        # explícitamente antes que aceptar ese comportamiento sorpresivo.
        if len(v.encode("utf-8")) > 72:
            raise ValueError("La contraseña no puede superar los 72 bytes (límite de bcrypt)")
        return v


class UsuarioOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    nombre: str
    email: EmailStr
    rol: RolUsuario
    creado_en: datetime


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    # El usuario elige explícitamente la estrategia en el momento del login; esta elección
    # no se persiste en ningún lado, es solo una instrucción de "qué devolver ahora".
    metodo: Literal["cookie", "jwt"]

    @field_validator("email")
    @classmethod
    def _normalizar_email(cls, v: str) -> str:
        return v.lower()


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginCookieResponse(BaseModel):
    mensaje: str
    usuario: UsuarioOut
