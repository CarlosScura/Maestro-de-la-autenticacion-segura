"""
Autenticación basada en JWT con `python-jose`.

Un JWT firmado (JWS) NO está cifrado: cualquiera que intercepte el token puede decodificar
el payload en base64 y leerlo, aunque no pueda modificarlo sin invalidar la firma. Para datos
sensibles como el email del usuario (dato de identidad en una plataforma de documentos), eso
no alcanza: si el token queda en un log, en el historial del navegador o en manos de un
proxy intermedio, no queremos que esa PII quede legible a simple vista. Por eso, además de
firmar el token completo, ciframos el email antes de meterlo como claim, usando Fernet
(cifrado simétrico autenticado de la librería `cryptography`, la misma que ya trae
`python-jose[cryptography]` como dependencia).
"""

import os
from datetime import datetime, timedelta, timezone

from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException, status
from jose import JWTError, jwt

# Valor por defecto solo para desarrollo local. En cualquier entorno real esto DEBE venir de
# una variable de entorno con un valor largo y aleatorio (ver .env.example).
CLAVE_SECRETA_JWT = os.getenv("JWT_SECRET_KEY", "clave-de-desarrollo-cambiar-en-produccion")
ALGORITMO_JWT = "HS256"
MINUTOS_EXPIRACION_JWT = int(os.getenv("JWT_EXPIRE_MINUTES", "30"))

_clave_cifrado_env = os.getenv("TOKEN_ENCRYPTION_KEY")
if _clave_cifrado_env:
    _fernet = Fernet(_clave_cifrado_env.encode("utf-8"))
else:
    # Sin esta variable en .env, generamos una clave nueva en cada arranque del proceso.
    # Sirve para que el proyecto no explote en desarrollo, pero implica que los tokens
    # emitidos antes de un reinicio del servidor quedan indescifrables después: para
    # cualquier uso real hay que fijar TOKEN_ENCRYPTION_KEY (Fernet.generate_key()).
    _fernet = Fernet(Fernet.generate_key())


def _cifrar_dato_sensible(valor: str) -> str:
    return _fernet.encrypt(valor.encode("utf-8")).decode("utf-8")


def _descifrar_dato_sensible(valor_cifrado: str) -> str:
    return _fernet.decrypt(valor_cifrado.encode("utf-8")).decode("utf-8")


def crear_token(usuario) -> str:
    """
    Genera un JWT firmado. El `sub` (subject) es el id del usuario, que es lo único que se
    necesita para volver a buscarlo en la base al validar el token; el rol viaja en el token
    para no tener que pegarle a la base en cada request solo para chequear permisos.
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
    Decodifica y valida la firma y expiración del token. `jwt.decode` ya rechaza tokens
    expirados o con firma inválida levantando `JWTError`; acá solo lo traducimos a un 401
    de HTTP para que el resto de la app no tenga que conocer la excepción de `jose`.
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
