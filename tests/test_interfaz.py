"""Tests de que la interfaz se sirve correctamente y es compatible con el CSP."""


def test_interfaz_se_sirve_en_la_raiz(client):
    respuesta = client.get("/")

    assert respuesta.status_code == 200
    assert "text/html" in respuesta.headers["content-type"]
    assert 'src="/static/app.js"' in respuesta.text


def test_estaticos_se_sirven_con_csp_estricto(client):
    for ruta in ("/static/app.js", "/static/styles.css"):
        respuesta = client.get(ruta)
        assert respuesta.status_code == 200
        assert respuesta.headers["content-security-policy"].startswith("default-src 'self'")


def test_html_no_tiene_scripts_ni_estilos_inline(client):
    # El CSP "default-src 'self'" bloquearía cualquier <script> o <style> inline, y la
    # interfaz dejaría de funcionar en el navegador sin que ningún otro test lo note.
    html = client.get("/").text

    assert "<script>" not in html
    assert "<style" not in html
    assert "onclick=" not in html
