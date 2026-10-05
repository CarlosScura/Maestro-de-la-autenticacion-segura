"""
Autenticación basada en JWT con `python-jose`.

"""

import os
from datetime import datetime, timedelta, timezone

from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException, status
from jose import JWTError, jwt

CLAVE_SECRETA_JWT = os.getenv("JWT_SECRET_KEY", "clave-de-desarrollo-cambiar-en-produccion")
ALGORITMO_JWT = "HS256"
MINUTOS_EXPIRACION_JWT = int(os.getenv("JWT_EXPIRE_MINUTES", "30"))

_clave_cifrado_env = os.getenv("TOKEN_ENCRYPTION_KEY")
if _clave_cifrado_env:
    _fernet = Fernet(_clave_cifrado_env.encode("utf-8"))
else:
    # Si no existe el TOKEN_ENCRYPTION_KEY en el .env
    _fernet = Fernet(Fernet.generate_key())


def _cifrar_dato_sensible(valor: str) -> str:
    return _fernet.encrypt(valor.encode("utf-8")).decode("utf-8")


def _descifrar_dato_sensible(valor_cifrado: str) -> str:
    return _fernet.decrypt(valor_cifrado.encode("utf-8")).decode("utf-8")


def crear_token(usuario) -> str:
    """
    Genera un JWT firmado. El `sub` (subject) es el id del usuario, que es lo único que se
    necesita para volver a buscarlo en la base al validar el token; el rol viaja en el token
    para solo para chequear permisos.
    """
    ahora = datetime.now(timezone.utc)
    expira = ahora + timedelta(minutes=MINUTOS_EXPIRACION_JWT)

    payload = {
        "sub": str(usuario.id),
        "rol": usuario.rol.value,
        "email_cifrado": _cifrar_dato_sensible(usuario.email),
        "iat": int(ahora.timestamp()),
        "exp": int(expira.timestamp()),
    }
    return jwt.encode(payload, CLAVE_SECRETA_JWT, algorithm=ALGORITMO_JWT)


def verificar_token(token: str) -> dict:
    """
    Decodifica y valida la firma y expiración del token.
    """
    try:
        return jwt.decode(token, CLAVE_SECRETA_JWT, algorithms=[ALGORITMO_JWT])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido o expirado",
        )


def obtener_email_desde_token(payload: dict) -> str:
    """Descifra el email embebido en el token, para el caso en que alguna ruta lo necesite."""
    try:
        return _descifrar_dato_sensible(payload["email_cifrado"])
    except (InvalidToken, KeyError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token corrupto")
