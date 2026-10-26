
import hmac
import ipaddress
import json
import os
import threading
import uuid

from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

LOG = Path(os.environ.get("LOG_FILE", "requests.jsonl"))
MAX_BODY_SIZE = 32_768
LOG_LOCK = threading.Lock()

HTML = r"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Diagnóstico técnico</title>
</head>
<body>
  <h1>Diagnóstico técnico del navegador</h1>
  <p>Esta página recoge características técnicas básicas
     del navegador para una prueba de diagnóstico.</p>
  <pre id="estado">Preparando diagnóstico…</pre>

  <script>
  async function diagnostico() {
    const datos = {
      userAgent: navigator.userAgent,
      idioma: navigator.language,
      idiomas: navigator.languages,
      zonaHoraria: Intl.DateTimeFormat()
        .resolvedOptions().timeZone,
      diferenciaUTC: new Date().getTimezoneOffset(),
      cookiesHabilitadas: navigator.cookieEnabled,

      pantalla: {
        ancho: screen.width,
        alto: screen.height,
        anchoDisponible: screen.availWidth,
        altoDisponible: screen.availHeight,
        profundidadColor: screen.colorDepth,
        pixelRatio: window.devicePixelRatio
      },

      ventana: {
        ancho: window.innerWidth,
        alto: window.innerHeight
      },

      hardware: {
        nucleosLogicos: navigator.hardwareConcurrency ?? null,
        memoriaGB: navigator.deviceMemory ?? null,
        puntosTactiles: navigator.maxTouchPoints
      },

      conexion: navigator.connection ? {
        tipoEfectivo: navigator.connection.effectiveType ?? null,
        downlinkMbps: navigator.connection.downlink ?? null,
        ahorroDatos: navigator.connection.saveData ?? null
      } : null,

      recopiladoUTC: new Date().toISOString()
    };

    try {
      const respuesta = await fetch("/telemetry", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(datos),
        cache: "no-store"
      });

      document.getElementById("estado").textContent =
        respuesta.ok
          ? "Diagnóstico enviado correctamente."
          : "No se pudo enviar el diagnóstico.";
    } catch (_) {
      document.getElementById("estado").textContent =
        "Error de conexión.";
    }
  }

  diagnostico();
  </script>
</body>
</html>
"""


def ahora_utc():
    return datetime.now(timezone.utc).isoformat()


def normalizar_ip(ip):
    """Normaliza una IP; no determina la identidad del usuario."""
    try:
        direccion = ipaddress.ip_address(ip)

        # Una IPv4 representada como IPv6 se normaliza a IPv4.
        if isinstance(direccion, ipaddress.IPv6Address):
            if direccion.ipv4_mapped:
                direccion = direccion.ipv4_mapped

        return {
            "direccion": str(direccion),
            "version": direccion.version,
            "privada": direccion.is_private,
            "loopback": direccion.is_loopback,
            "global": direccion.is_global
        }
    except ValueError:
        return {
            "direccion": None,
            "version": None,
            "privada": None,
            "loopback": None,
            "global": None
        }


def registrar(evento):
    """Imprime en stdout (pestaña Logs de Render) y guarda en archivo."""
    linea = json.dumps(evento, ensure_ascii=False)
    print(linea, flush=True)

    with LOG_LOCK:
        with LOG.open("a", encoding="utf-8") as archivo:
            archivo.write(linea + "\n")


class Handler(BaseHTTPRequestHandler):

    server_version = "DiagnosticServer"
    sys_version = ""

    def ip_cliente(self):
        """IP real del visitante: detrás de Render llega por cabeceras."""
        for h in ("CF-Connecting-IP", "True-Client-IP"):
            v = self.headers.get(h)
            if v:
                return v.strip()

        xff = self.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()

        return self.client_address[0]

    def registrar_peticion(self, datos_cliente=None):
        evento = {
            "id": str(uuid.uuid4()),
            "timestamp_utc": ahora_utc(),
            "ip_observada": normalizar_ip(self.ip_cliente()),
            "x_forwarded_for": self.headers.get("X-Forwarded-For"),
            "cf_connecting_ip": self.headers.get("CF-Connecting-IP"),
            "metodo": self.command,
            "ruta": urlparse(self.path).path,
            "user_agent": self.headers.get("User-Agent"),
            "accept_language": self.headers.get("Accept-Language"),
            "referer": self.headers.get("Referer"),
            "content_type": self.headers.get("Content-Type"),
            "datos_cliente": datos_cliente
        }

        registrar(evento)

    def responder(self, codigo, contenido, tipo):
        cuerpo = contenido.encode("utf-8")

        self.send_response(codigo)
        self.send_header("Content-Type", tipo)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(cuerpo)))
        self.end_headers()

        try:
            if self.command != "HEAD":
                self.wfile.write(cuerpo)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_HEAD(self):
        # Para monitores tipo UptimeRobot: no se registra nada.
        self.responder(200, "ok", "text/plain; charset=utf-8")

    def do_GET(self):
        partes = urlparse(self.path)
        ruta = partes.path

        # Endpoint de salud para mantener el servicio despierto (no se registra).
        if ruta == "/health":
            self.responder(200, "ok", "text/plain; charset=utf-8")
            return

        # Descarga protegida del archivo de registros (no se registra).
        if ruta == "/logs":
            token = parse_qs(partes.query).get("token", [""])[0]
            esperado = os.environ.get("LOG_TOKEN", "")

            if esperado and hmac.compare_digest(token, esperado):
                contenido = (
                    LOG.read_text(encoding="utf-8") if LOG.exists() else ""
                )
                self.responder(200, contenido, "text/plain; charset=utf-8")
            else:
                self.responder(
                    404, "No encontrado", "text/plain; charset=utf-8"
                )
            return

        if ruta != "/":
            self.responder(
                404, "No encontrado", "text/plain; charset=utf-8"
            )
            return

        self.registrar_peticion()
        self.responder(200, HTML, "text/html; charset=utf-8")

    def do_POST(self):
        if urlparse(self.path).path != "/telemetry":
            self.responder(
                404, "No encontrado", "text/plain; charset=utf-8"
            )
            return

        try:
            longitud = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.responder(
                400, "Longitud no válida", "text/plain; charset=utf-8"
            )
            return

        if not 1 <= longitud <= MAX_BODY_SIZE:
            self.responder(
                413, "Tamaño no permitido", "text/plain; charset=utf-8"
            )
            return

        if self.headers.get_content_type() != "application/json":
            self.responder(
                415, "Se requiere JSON", "text/plain; charset=utf-8"
            )
            return

        try:
            cuerpo = self.rfile.read(longitud)
            datos = json.loads(cuerpo.decode("utf-8"))

            if not isinstance(datos, dict):
                raise ValueError("El JSON debe ser un objeto")

            self.registrar_peticion(datos_cliente=datos)

            self.responder(200, '{"ok":true}', "application/json")

        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            self.responder(
                400, "JSON no válido", "text/plain; charset=utf-8"
            )

    def log_message(self, formato, *args):
        # Los eventos se guardan en el archivo JSONL y en stdout.
        pass


if __name__ == "__main__":
    puerto = int(os.environ.get("PORT", "8080"))
    servidor = ThreadingHTTPServer(("0.0.0.0", puerto), Handler)

    print(f"Servidor escuchando en el puerto {puerto}", flush=True)
    print(f"Archivo de registros: {LOG.resolve()}", flush=True)

    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        print("\nCerrando servidor.")
    finally:
        servidor.server_close()