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

        # No mandar la URL completa de referencia a otros orígenes (puede filtrar tokens o
        # ids en la query string); solo el origen cuando se navega a otro sitio.
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Deshabilita por defecto APIs del navegador que esta API no necesita usar.
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        # Se excluyen /docs, /redoc y /openapi.json porque Swagger UI/ReDoc cargan su CSS/JS
        # y favicon desde el CDN de jsdelivr (script-src/style-src externos), algo que
        # "default-src 'self'" bloquea.
        if request.url.path not in ("/docs", "/redoc", "/openapi.json"):
            response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"

        # Fuerza HTTPS en cada visita futura, incluyendo subdominios. 
        # Solo tiene efecto real si la API efectivamente se sirve por HTTPS.
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"

        # El viejo filtro X-XSS-Protection de los navegadores basados en WebKit/Blink tenía
        # bugs que un atacante podía explotar para *inducir* fugas de información en algunos
        # escenarios; los navegadores modernos ya lo tienen deprecado y confían en la
        # Content-Security-Policy de arriba. Se setea en "0" (desactivado) explícitamente en
        # vez de "1", siguiendo la recomendación actual de OWASP.
        response.headers["X-XSS-Protection"] = "0"

        return response
