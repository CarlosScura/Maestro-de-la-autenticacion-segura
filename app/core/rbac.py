"""
Resolución de "quién hace esta request" (autenticación dual) y control de acceso por rol
(autorización).
"""

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app import models
from app.core.jwt_handler import verificar_token
from app.core.sessions import verificar_sesion
from app.database import get_db


def obtener_usuario_actual(request: Request, db: Session = Depends(get_db)) -> models.Usuario:
    """
    Dependencia central de autenticación. 
    En cada request mira qué llegó y decide.
    """
    encabezado_auth = request.headers.get("Authorization")
    if encabezado_auth and encabezado_auth.startswith("Bearer "):
        token = encabezado_auth.removeprefix("Bearer ").strip()
        payload = verificar_token(token)

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
    Factory de dependencias: En una ruta
    exige que el usuario ya autenticado tenga uno de los roles indicados. Se construye como
    factory para poder reutilizar la misma lógica con
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
