"""
Resolución de "quién hace esta request" (autenticación dual) y control de acceso por rol
(autorización).

Van juntos en este archivo a propósito: las dependencias de autorización por rol necesitan,
como primer paso, saber quién es el usuario autenticado, y ese paso es exactamente donde
vive la lógica de "cookie o JWT" descripta en el enunciado.
"""

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app import models
from app.core.jwt_handler import verificar_token
from app.core.sessions import verificar_sesion
from app.database import get_db


def obtener_usuario_actual(request: Request, db: Session = Depends(get_db)) -> models.Usuario:
    """
    Dependencia central de autenticación. No usa la elección que el usuario hizo en el login
    (esa elección no se guarda en ningún lado): en cada request mira qué llegó y decide sobre
    la marcha.

    1. Si viene un header `Authorization: Bearer <token>`, se valida como JWT.
    2. Si no, si viene la cookie de sesión, se busca esa sesión.
    3. Si no viene ninguna de las dos, no está autenticado.
    """
    encabezado_auth = request.headers.get("Authorization")
    if encabezado_auth and encabezado_auth.startswith("Bearer "):
        token = encabezado_auth.removeprefix("Bearer ").strip()
        payload = verificar_token(token)  # levanta 401 si el JWT es inválido o expiró

        usuario = db.get(models.Usuario, int(payload["sub"]))
        if usuario is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuario no encontrado")
        return usuario

    token_sesion = request.cookies.get("session_id")
    if token_sesion:
        usuario = verificar_sesion(db, token_sesion)
        if usuario is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Sesión inválida o expirada"
            )
        return usuario

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No autenticado")


def requerir_rol(*roles_permitidos: models.RolUsuario):
    """
    Factory de dependencias: `Depends(requerir_rol(RolUsuario.ADMINISTRADOR))` en una ruta
    exige que el usuario ya autenticado tenga uno de los roles indicados. Se construye como
    factory (función que devuelve una dependencia) para poder reutilizar la misma lógica con
    distintas combinaciones de roles en distintas rutas, sin duplicar código.
    """

    def _dependencia(
        usuario_actual: models.Usuario = Depends(obtener_usuario_actual),
    ) -> models.Usuario:
        if usuario_actual.rol not in roles_permitidos:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No tenés permisos para realizar esta acción",
            )
        return usuario_actual

    return _dependencia
