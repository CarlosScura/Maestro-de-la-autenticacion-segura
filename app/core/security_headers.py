"""
Middleware que agrega cabeceras HTTP de seguridad a toda respuesta de la API.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        # Evita que el navegador "adivine" el tipo de contenido de una respuesta
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Impide que esta API se embeba dentro de un <iframe> de otro sitio (mitiga clickjacking).
        response.headers["X-Frame-Options"] = "DENY"

        # No mandar la URL completa de referencia a otros orígenes.
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Deshabilita por defecto APIs del navegador que esta API no necesita usar.
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        # Se excluyen /docs, /redoc y /openapi.json porque Swagger UI/ReDoc cargan su CSS/JS
        if request.url.path not in ("/docs", "/redoc", "/openapi.json"):
            response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"

        # Fuerza HTTPS en cada visita futura, incluyendo subdominios.
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"

        #  Se setea en "0" siguiendo la recomendación actual de OWASP.
        response.headers["X-XSS-Protection"] = "0"

        return response
