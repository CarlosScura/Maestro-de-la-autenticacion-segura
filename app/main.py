"""
Punto de entrada: arranca la app, registra routers y middleware.
"""

from fastapi import FastAPI

from app.core.security_headers import SecurityHeadersMiddleware
from app.database import Base, engine
from app.routers import auth

# create_all() alcanza para esta primera versión (crea las tablas si no existen, sin tocar
# las que ya existen). No reemplaza a una herramienta de migraciones real: si más adelante
# se necesita versionar cambios de esquema en una base con datos, esto se debería migrar a
# Alembic, pero eso queda fuera del alcance actual.
Base.metadata.create_all(bind=engine)

app = FastAPI(title="PassPort Inc. — Sistema de Gestión de Sesiones y Autenticación")

app.add_middleware(SecurityHeadersMiddleware)
app.include_router(auth.router)


@app.get("/salud")
def salud():
    return {"estado": "ok"}
