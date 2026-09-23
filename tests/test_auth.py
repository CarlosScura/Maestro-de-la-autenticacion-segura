"""
Tests de punta a punta de los endpoints de autenticación, a través de la API real (TestClient)
y contra una base de datos exclusiva para tests (ver conftest.py).
"""

from app.core.csrf import NOMBRE_COOKIE_CSRF, NOMBRE_HEADER_CSRF
from app.core.sessions import NOMBRE_COOKIE_SESION
from tests.conftest import PASSWORD_VALIDA, headers_jwt, login


# --- Registro ---------------------------------------------------------------------------


def test_registro_exitoso(client):
    respuesta = client.post(
        "/auth/registro",
        json={"nombre": "Ana", "email": "Ana@Ejemplo.com", "password": PASSWORD_VALIDA},
    )

    assert respuesta.status_code == 201
    cuerpo = respuesta.json()
    assert cuerpo["email"] == "ana@ejemplo.com"
    assert cuerpo["rol"] == "usuario"
    # Nunca se debe devolver la contraseña ni su hash.
    assert "password" not in cuerpo and "password_hash" not in cuerpo


def test_registro_con_email_duplicado_falla(client, usuario):
    respuesta = client.post(
        "/auth/registro",
        json={"nombre": "Otra Ana", "email": usuario["email"], "password": PASSWORD_VALIDA},
    )

    assert respuesta.status_code == 400


# --- Login ------------------------------------------------------------------------------


def test_login_por_cookie_exitoso(client, usuario):
    respuesta = login(client, usuario, "cookie")

    assert respuesta.status_code == 200
    assert NOMBRE_COOKIE_SESION in client.cookies
    assert NOMBRE_COOKIE_CSRF in client.cookies
    # La cookie de sesión debe ser HttpOnly (JS no la puede leer); la de CSRF no, porque el
    # frontend necesita leerla para copiarla al header.
    set_cookies = respuesta.headers.get_list("set-cookie")
    cookie_sesion = next(c for c in set_cookies if c.startswith(f"{NOMBRE_COOKIE_SESION}="))
    cookie_csrf = next(c for c in set_cookies if c.startswith(f"{NOMBRE_COOKIE_CSRF}="))
    assert "httponly" in cookie_sesion.lower()
    assert "httponly" not in cookie_csrf.lower()


def test_login_por_jwt_exitoso(client, usuario):
    respuesta = login(client, usuario, "jwt")

    assert respuesta.status_code == 200
    cuerpo = respuesta.json()
    assert cuerpo["token_type"] == "bearer"
    assert cuerpo["access_token"]
    # Con JWT no se crea sesión de servidor.
    assert NOMBRE_COOKIE_SESION not in client.cookies


def test_login_con_password_incorrecta_falla(client, usuario):
    respuesta = login(client, {**usuario, "password": "otra-cosa-123"}, "cookie")

    assert respuesta.status_code == 401
    assert NOMBRE_COOKIE_SESION not in client.cookies


def test_login_con_email_inexistente_falla(client):
    respuesta = login(client, {"email": "nadie@ejemplo.com", "password": PASSWORD_VALIDA}, "jwt")

    assert respuesta.status_code == 401


# --- Rutas protegidas -------------------------------------------------------------------


def test_perfil_con_jwt_valido(client, usuario):
    respuesta = client.get("/auth/perfil", headers=headers_jwt(client, usuario))

    assert respuesta.status_code == 200
    assert respuesta.json()["email"] == usuario["email"]


def test_perfil_con_cookie_valida(client, usuario):
    login(client, usuario, "cookie")

    respuesta = client.get("/auth/perfil")

    assert respuesta.status_code == 200
    assert respuesta.json()["email"] == usuario["email"]


def test_perfil_sin_autenticacion_devuelve_401(client):
    assert client.get("/auth/perfil").status_code == 401


def test_perfil_con_jwt_adulterado_devuelve_401(client, usuario):
    headers = headers_jwt(client, usuario)
    headers["Authorization"] += "x"

    assert client.get("/auth/perfil", headers=headers).status_code == 401


# --- RBAC -------------------------------------------------------------------------------


def test_admin_puede_listar_usuarios(client, admin, usuario):
    respuesta = client.get("/auth/admin/usuarios", headers=headers_jwt(client, admin))

    assert respuesta.status_code == 200
    emails = {u["email"] for u in respuesta.json()}
    assert emails == {admin["email"], usuario["email"]}


def test_admin_por_cookie_puede_listar_usuarios(client, admin):
    login(client, admin, "cookie")

    assert client.get("/auth/admin/usuarios").status_code == 200


def test_usuario_comun_recibe_403_en_ruta_de_admin(client, usuario):
    respuesta = client.get("/auth/admin/usuarios", headers=headers_jwt(client, usuario))

    assert respuesta.status_code == 403


# --- Logout y CSRF ----------------------------------------------------------------------


def test_logout_por_cookie_con_header_csrf_funciona_e_invalida_la_sesion(client, usuario):
    """Regresión del bug del 403: con el header X-CSRF-Token correcto, el logout funciona."""
    login(client, usuario, "cookie")
    token_sesion = client.cookies[NOMBRE_COOKIE_SESION]
    token_csrf = client.cookies[NOMBRE_COOKIE_CSRF]

    # Lo mismo que hace app/static/app.js: copiar la cookie csrf_token al header.
    respuesta = client.post("/auth/logout", headers={NOMBRE_HEADER_CSRF: token_csrf})

    assert respuesta.status_code == 200
    assert NOMBRE_COOKIE_SESION not in client.cookies

    # Aunque alguien hubiera copiado el valor viejo de la cookie, la sesión se borró de la
    # base: reenviarla a mano ya no autentica.
    client.cookies.set(NOMBRE_COOKIE_SESION, token_sesion)
    assert client.get("/auth/perfil").status_code == 401


def test_logout_por_cookie_sin_header_csrf_devuelve_403(client, usuario):
    """La protección CSRF sigue activa: sin el header (lo que haría un sitio atacante) falla."""
    login(client, usuario, "cookie")

    respuesta = client.post("/auth/logout")

    assert respuesta.status_code == 403
    # Y la sesión sigue viva, porque el logout no llegó a ejecutarse.
    assert client.get("/auth/perfil").status_code == 200


def test_logout_por_cookie_con_header_csrf_incorrecto_devuelve_403(client, usuario):
    login(client, usuario, "cookie")

    respuesta = client.post("/auth/logout", headers={NOMBRE_HEADER_CSRF: "valor-inventado"})

    assert respuesta.status_code == 403


def test_logout_por_jwt_no_exige_csrf(client, usuario):
    # Con JWT no hay sesión en el servidor para invalidar: el logout no guarda estado y el
    # token sigue siendo válido hasta que expira (el cliente es quien lo descarta). Por eso
    # acá solo se verifica que el logout responde 200 sin CSRF, y la invalidación de la
    # sesión se prueba en el test de cookie.
    respuesta = client.post("/auth/logout", headers=headers_jwt(client, usuario))

    assert respuesta.status_code == 200


# --- Rate limiting ----------------------------------------------------------------------


def test_bloqueo_tras_varios_intentos_fallidos(client, usuario):
    credenciales_malas = {**usuario, "password": "incorrecta-123"}

    # Los umbrales están en app/core/rate_limit.py: a partir de 3 fallos se bloquea 30 s.
    for _ in range(3):
        assert login(client, credenciales_malas, "jwt").status_code == 401

    bloqueado = login(client, credenciales_malas, "jwt")
    assert bloqueado.status_code == 429
    assert int(bloqueado.headers["Retry-After"]) > 0

    # Durante el bloqueo, ni siquiera la contraseña correcta deja entrar.
    assert login(client, usuario, "jwt").status_code == 429


def test_login_exitoso_resetea_el_contador_de_fallos(client, usuario):
    credenciales_malas = {**usuario, "password": "incorrecta-123"}
    for _ in range(2):
        login(client, credenciales_malas, "jwt")

    assert login(client, usuario, "jwt").status_code == 200

    # Si el contador no se hubiera reseteado, el 3er fallo total ya dispararía el bloqueo.
    for _ in range(2):
        assert login(client, credenciales_malas, "jwt").status_code == 401
