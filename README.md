# Maestro-de-la-autenticacion-segura
Decimo Challenge en The Huddle, Autenticación, Cookies, XSS y CSRF.

## PassPort Inc. — Sistema de Gestión de Sesiones y Autenticación

Backend con FastAPI que implementa autenticación dual (cookie de sesión o JWT, a elección
del usuario en el momento del login), roles (Usuario / Administrador), CSRF, rate limiting
progresivo y cabeceras de seguridad. Ver [prompt-challenge10.md](prompt-challenge10.md) para
la especificación completa.

### Cómo correrlo

1. Tener PostgreSQL corriendo y crear la base de datos (por ejemplo `passport_db`).
2. Crear un entorno virtual e instalar dependencias:

   ```bash
   python3.13 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

3. Copiar `.env.example` a `.env` y completar `JWT_SECRET_KEY`, `TOKEN_ENCRYPTION_KEY` y
   `DATABASE_URL` (el archivo trae los comandos para generar cada clave).
4. Levantar el servidor:

   ```bash
   uvicorn app.main:app --reload
   ```

5. Documentación interactiva en `http://localhost:8000/docs`.

Las tablas se crean automáticamente al arrancar (`Base.metadata.create_all`). El registro
público (`POST /auth/registro`) siempre crea usuarios con rol `usuario`; para tener un
administrador de prueba hay que actualizar esa fila a mano en la base:

```sql
UPDATE usuarios SET rol = 'administrador' WHERE email = 'tu-email@ejemplo.com';
```

### Interfaz

Con el servidor levantado, abrir `http://localhost:8000/`. Permite registrarse, loguearse
por cookie o por JWT, ver el perfil, listar usuarios (solo admin) y hacer logout, sin usar
`curl`. Está hecha con HTML, CSS y JS sin frameworks en `app/static/`. El JS se encarga de
copiar la cookie `csrf_token` al header `X-CSRF-Token` en el logout (patrón double submit
cookie) y de mandar el JWT en `Authorization: Bearer`.

### Tests

Usan una base PostgreSQL separada (`passport_test_db` por defecto, en el mismo servidor y
con el mismo usuario que `DATABASE_URL`). Cada test borra y recrea sus tablas, así que
**nunca** debe apuntar a la base de desarrollo (el `conftest.py` lo impide).

1. Crear la base una sola vez (con el usuario dueño de la base de desarrollo):
   ```bash
   createdb -O <tu_usuario> passport_test_db
   ```
2. Instalar las dependencias de desarrollo y correr:
   ```bash
   pip install -r requirements-dev.txt
   pytest
   ```

Para usar otra base, definir `TEST_DATABASE_URL` (en el entorno o en `.env`).

### Alcance

Sin recuperación de contraseña por email y sin Docker (se corre localmente). Ver el detalle
de requerimientos en [prompt-challenge10.md](prompt-challenge10.md) y
[prompt-challenge10-2.md](prompt-challenge10-2.md).
