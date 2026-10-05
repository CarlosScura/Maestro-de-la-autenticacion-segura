"""
Protección CSRF mediante el patrón "double submit cookie".

Solo tiene sentido para la autenticación por cookie. 
"""

import os
import secrets

from fastapi import HTTPException, Request, Response, status

NOMBRE_COOKIE_CSRF = "csrf_token"
NOMBRE_HEADER_CSRF = "X-CSRF-Token"

_COOKIE_SECURE = os.getenv("COOKIE_SECURE", "true").lower() == "true"


def generar_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def setear_cookie_csrf(response: Response, token: str) -> None:
    response.set_cookie(
        key=NOMBRE_COOKIE_CSRF,
        value=token,
        # Un atacante cross-site puede
        # hacer que el navegador ENVÍE la cookie automáticamente, 
        # pero no puede LEER su valor (la política de mismo origen se lo impide).
        httponly=False,
        secure=_COOKIE_SECURE,
        samesite="lax",
        path="/",
    )


def borrar_cookie_csrf(response: Response) -> None:
    response.delete_cookie(key=NOMBRE_COOKIE_CSRF, path="/")


def validar_csrf(request: Request) -> None:
    """
    Dependencia para usar en rutas que cambian estado (logout, y cualquier otra que se agregue
    más adelante) cuando el usuario puede estar autenticado por cookie.
    """
    encabezado_auth = request.headers.get("Authorization")
    if encabezado_auth and encabezado_auth.startswith("Bearer "):
        return

    token_cookie = request.cookies.get(NOMBRE_COOKIE_CSRF)
    token_header = request.headers.get(NOMBRE_HEADER_CSRF)

    # compare_digest en vez de "==" para no filtrar por temporización.
    if not token_cookie or not token_header or not secrets.compare_digest(token_cookie, token_header):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Token CSRF ausente o inválido"
        )
