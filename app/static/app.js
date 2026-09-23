"use strict";

/*
 * Cliente mínimo de la API de PassPort Inc.
 *
 * Soporta los dos métodos de autenticación del backend:
 *   - cookie: el navegador guarda y reenvía solo la cookie de sesión (HttpOnly). Lo único que
 *     tiene que hacer este script es copiar la cookie csrf_token al header X-CSRF-Token en las
 *     requests que cambian estado (double submit cookie, ver app/core/csrf.py).
 *   - jwt: el access_token vive en una variable de este script y se manda a mano en el header
 *     Authorization: Bearer <token>.
 */

const NOMBRE_COOKIE_CSRF = "csrf_token";
const NOMBRE_HEADER_CSRF = "X-CSRF-Token";

// El JWT se guarda solo en memoria (no en localStorage ni sessionStorage) a propósito: si
// algún día se colara un XSS, el script inyectado no encontraría el token en ningún storage
// persistente, y el token desaparece al cerrar o recargar la pestaña. La contra es que al
// recargar hay que volver a loguearse, algo aceptable para una interfaz de prueba.
let tokenJwt = null;

function leerCookie(nombre) {
  // document.cookie solo expone las cookies SIN HttpOnly: csrf_token es visible (debe
  // serlo para que el patrón funcione), session_id no (el JS nunca puede robarla).
  for (const par of document.cookie.split("; ")) {
    const [clave, ...resto] = par.split("=");
    if (clave === nombre) {
      return decodeURIComponent(resto.join("="));
    }
  }
  return null;
}

function construirHeaders({ conCsrf = false, conJson = false } = {}) {
  const headers = {};
  if (conJson) {
    headers["Content-Type"] = "application/json";
  }
  if (tokenJwt) {
    headers["Authorization"] = `Bearer ${tokenJwt}`;
  }
  if (conCsrf) {
    // Este es el fix del 403 en /auth/logout: el navegador manda la cookie csrf_token solo,
    // pero el servidor exige que el MISMO valor llegue también en un header. Un sitio
    // atacante puede lograr que el navegador envíe la cookie, pero no puede leerla (política
    // de mismo origen), así que no puede armar este header. Nosotros sí, porque esta página
    // se sirve desde el mismo origen que la API.
    // Con JWT el backend ignora el CSRF (el header Authorization no se envía solo en
    // requests cross-site), pero mandarlo igual no molesta si hay cookie.
    const tokenCsrf = leerCookie(NOMBRE_COOKIE_CSRF);
    if (tokenCsrf) {
      headers[NOMBRE_HEADER_CSRF] = tokenCsrf;
    }
  }
  return headers;
}

async function llamarApi(metodo, ruta, { cuerpo, conCsrf = false } = {}) {
  // fetch en mismo origen usa credentials: "same-origin" por defecto, así que la cookie de
  // sesión viaja sola sin configurar nada.
  const respuesta = await fetch(ruta, {
    method: metodo,
    headers: construirHeaders({ conCsrf, conJson: cuerpo !== undefined }),
    body: cuerpo !== undefined ? JSON.stringify(cuerpo) : undefined,
  });
  let datos = null;
  try {
    datos = await respuesta.json();
  } catch {
    // Respuesta sin cuerpo JSON: se muestra solo el código de estado.
  }
  return { ok: respuesta.ok, status: respuesta.status, datos };
}

function mostrarResultado(titulo, { ok, status, datos }) {
  const pre = document.getElementById("resultado");
  // textContent (nunca innerHTML): cualquier dato que venga del servidor se muestra como
  // texto plano y no puede inyectar HTML ni scripts en la página.
  pre.textContent = `${titulo} → ${status}\n\n${JSON.stringify(datos, null, 2)}`;
  pre.classList.toggle("error", !ok);
}

function actualizarEstado() {
  const estado = document.getElementById("estado-sesion");
  if (tokenJwt) {
    estado.textContent = "Autenticado por JWT (token en memoria)";
  } else if (leerCookie(NOMBRE_COOKIE_CSRF)) {
    estado.textContent = "Autenticado por cookie de sesión";
  } else {
    estado.textContent = "No autenticado";
  }
}

function datosDelFormulario(formulario) {
  return Object.fromEntries(new FormData(formulario).entries());
}

async function registrar(evento) {
  evento.preventDefault();
  const resultado = await llamarApi("POST", "/auth/registro", {
    cuerpo: datosDelFormulario(evento.target),
  });
  mostrarResultado("Registro", resultado);
  if (resultado.ok) {
    evento.target.reset();
  }
}

async function iniciarSesion(evento) {
  evento.preventDefault();
  const datos = datosDelFormulario(evento.target);

  // Se descarta cualquier JWT previo antes de loguear: si quedara, el header Authorization
  // tendría prioridad en el backend y un nuevo login por cookie no se "vería".
  tokenJwt = null;

  const resultado = await llamarApi("POST", "/auth/login", { cuerpo: datos });
  if (resultado.ok && datos.metodo === "jwt") {
    tokenJwt = resultado.datos.access_token;
  }
  // Con método cookie no hay nada que guardar a mano: el Set-Cookie de la respuesta ya dejó
  // session_id (HttpOnly) y csrf_token en el navegador, y leerCookie() toma este último
  // cuando haga falta.

  mostrarResultado("Login", resultado);
  actualizarEstado();
  if (resultado.ok) {
    evento.target.querySelector("[name=password]").value = "";
  }
}

async function verPerfil() {
  const resultado = await llamarApi("GET", "/auth/perfil");
  mostrarResultado("Perfil", resultado);
}

async function listarUsuarios() {
  const resultado = await llamarApi("GET", "/auth/admin/usuarios");
  mostrarResultado("Usuarios (admin)", resultado);
}

async function cerrarSesion() {
  const resultado = await llamarApi("POST", "/auth/logout", { conCsrf: true });
  if (resultado.ok) {
    // Con JWT el logout del servidor no guarda estado: el token seguiría siendo válido hasta
    // expirar, así que "cerrar sesión" en el cliente significa olvidarlo.
    tokenJwt = null;
  }
  mostrarResultado("Logout", resultado);
  actualizarEstado();
}

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("form-registro").addEventListener("submit", registrar);
  document.getElementById("form-login").addEventListener("submit", iniciarSesion);
  document.getElementById("btn-perfil").addEventListener("click", verPerfil);
  document.getElementById("btn-admin").addEventListener("click", listarUsuarios);
  document.getElementById("btn-logout").addEventListener("click", cerrarSesion);
  actualizarEstado();
});
