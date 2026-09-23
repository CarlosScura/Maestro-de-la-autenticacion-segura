"""
Punto de entrada: arranca la app, registra routers y middleware.
"""

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.core.security_headers import SecurityHeadersMiddleware
from app.database import Base, engine
from app.routers import auth

Base.metadata.create_all(bind=engine)

# La interfaz se sirve desde la misma app (mismo origen que la API): así la cookie de sesión
# viaja sola en cada fetch, el JS puede leer la cookie csrf_token, y el CSP "default-src 'self'"
# permite cargar app.js y styles.css sin tener que aflojar ninguna cabecera de seguridad.
DIRECTORIO_STATIC = Path(__file__).parent / "static"

app = FastAPI(title="PassPort Inc. — Sistema de Gestión de Sesiones y Autenticación")

app.add_middleware(SecurityHeadersMiddleware)
app.include_router(auth.router)
app.mount("/static", StaticFiles(directory=DIRECTORIO_STATIC), name="static")


@app.get("/", include_in_schema=False)
def interfaz():
    return FileResponse(DIRECTORIO_STATIC / "index.html")


@app.get("/salud")
def salud():
    return {"estado": "ok"}
