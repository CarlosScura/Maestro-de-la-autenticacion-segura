"""
Endpoints de autenticación: registro, login y logout.
"""

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app import models, schemas
from app.core.csrf import (
    borrar_cookie_csrf,
    generar_csrf_token,
    setear_cookie_csrf,
    validar_csrf,
)
from app.core.hashing import hashear_password, verificar_password
from app.core.jwt_handler import crear_token
from app.core.rate_limit import (
    limpiar_intentos_fallidos,
    registrar_intento_fallido,
    verificar_bloqueo,
)
from app.core.rbac import obtener_usuario_actual, requerir_rol
from app.core.sessions import (
    NOMBRE_COOKIE_SESION,
    borrar_cookie_sesion,
    crear_sesion,
    eliminar_sesion,
    setear_cookie_sesion,
)
from app.database import get_db
from app.models import RolUsuario

router = APIRouter(prefix="/auth", tags=["autenticación"])


@router.post("/registro", response_model=schemas.UsuarioOut, status_code=status.HTTP_201_CREATED)
def registrar_usuario(datos: schemas.UsuarioRegistro, db: Session = Depends(get_db)):
    ya_existe = db.query(models.Usuario).filter(models.Usuario.email == datos.email).first()
    if ya_existe:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="No se pudo completar el registro"
        )

    nuevo_usuario = models.Usuario(
        nombre=datos.nombre,
        email=datos.email,
        password_hash=hashear_password(datos.password),
        rol=RolUsuario.USUARIO,
    )
    db.add(nuevo_usuario)
    db.commit()
    db.refresh(nuevo_usuario)
    return nuevo_usuario


@router.post("/login")
def iniciar_sesion(datos: schemas.LoginRequest, response: Response, db: Session = Depends(get_db)):
    verificar_bloqueo(db, datos.email)

    usuario = db.query(models.Usuario).filter(models.Usuario.email == datos.email).first()
    credenciales_validas = usuario is not None and verificar_password(datos.password, usuario.password_hash)

    if not credenciales_validas:
        registrar_intento_fallido(db, datos.email)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Email o contraseña incorrectos")

    limpiar_intentos_fallidos(db, datos.email)

    if datos.metodo == "jwt":
        token = crear_token(usuario)
        return schemas.TokenResponse(access_token=token)

    # metodo == "cookie"
    token_sesion = crear_sesion(db, usuario)
    setear_cookie_sesion(response, token_sesion)
    setear_cookie_csrf(response, generar_csrf_token())
    return schemas.LoginCookieResponse(mensaje="Sesión iniciada correctamente", usuario=usuario)


@router.post("/logout", dependencies=[Depends(validar_csrf)])
def cerrar_sesion(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    usuario_actual: models.Usuario = Depends(obtener_usuario_actual),
):
    # Si el usuario se autenticó con cookie, hay una sesión en la base para invalidar.
    # Si se autenticó con JWT, el logout es "stateless": no hay nada que borrar del lado del
    # servidor (el token sigue siendo técnicamente válido hasta que expira por sí solo); el
    # cliente simplemente debe descartarlo. Implementar una lista negra de JWT queda fuera
    # del alcance de esta primera versión.
    token_sesion = request.cookies.get(NOMBRE_COOKIE_SESION)
    if token_sesion:
        eliminar_sesion(db, token_sesion)
        borrar_cookie_sesion(response)
        borrar_cookie_csrf(response)

    return {"mensaje": "Sesión cerrada correctamente"}


@router.get("/perfil", response_model=schemas.UsuarioOut)
def obtener_perfil(usuario_actual: models.Usuario = Depends(obtener_usuario_actual)):
    """Ruta protegida de ejemplo: accesible para cualquier usuario autenticado (ambos roles)."""
    return usuario_actual


@router.get("/admin/usuarios", response_model=list[schemas.UsuarioOut])
def listar_usuarios(
    db: Session = Depends(get_db),
    _usuario_admin: models.Usuario = Depends(requerir_rol(RolUsuario.ADMINISTRADOR)),
):
    """Ruta protegida de ejemplo: solo para Administrador, demuestra el RBAC por rol."""
    return db.query(models.Usuario).all()
