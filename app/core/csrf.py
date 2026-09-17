"""
Protección CSRF mediante el patrón "double submit cookie".

Solo tiene sentido para la autenticación por cookie: un JWT que viaja en el header
`Authorization` no lo agrega el navegador automáticamente en requests cross-site (a
diferencia de una cookie), así que un sitio malicioso no puede forzar a la víctima a
enviarlo. La cookie de sesión sí viaja sola con cada request al dominio, y ahí es donde un
atacante podría, por ejemplo, hacer que el navegador de la víctima dispare un POST /logout
sin que la víctima lo sepa. Por eso `validar_csrf` no exige nada cuando detecta que la
request se autenticó con un Bearer token.
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
        # A diferencia de la cookie de sesión, esta debe poder leerla JavaScript en el
        # cliente: el patrón "double submit" consiste justamente en que el frontend lee este
        # valor y lo reenvía a mano en el header X-CSRF-Token. Un atacante cross-site puede
        # hacer que el navegador ENVÍE la cookie automáticamente, pero no puede LEER su valor
        # (la política de mismo origen se lo impide), así que no puede reconstruir el header.
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

    # compare_digest en vez de "==" para no filtrar por temporización cuánto del token
    # coincide caracter a caracter.
    if not token_cookie or not token_header or not secrets.compare_digest(token_cookie, token_header):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Token CSRF ausente o inválido"
        )
