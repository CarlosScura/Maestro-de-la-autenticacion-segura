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

### Alcance de esta primera versión

Sin interfaz gráfica, sin tests automatizados, sin recuperación de contraseña por email y
sin Docker (se corre localmente) — ver el detalle de requerimientos y las decisiones de
diseño en [prompt-challenge10.md](prompt-challenge10.md).
