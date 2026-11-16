"""Pruebas: python test_scanner.py"""
import socket
import threading

import os
import tempfile

from scanner import detect_software, parse_ports, scan, summarize_banner, write_report

# 1. El parser entiende listas, rangos y quita duplicados
assert parse_ports("22,80,80,8000-8002") == [22, 80, 8000, 8001, 8002]
for bad in ("0", "70000", ""):
    try:
        parse_ports(bad)
        raise AssertionError(f"debió fallar con {bad!r}")
    except ValueError:
        pass

# 2. Levantamos un servidor falso que anuncia un banner tipo SSH
server = socket.socket()
server.bind(("127.0.0.1", 0))  # puerto 0 = el sistema elige uno libre
server.listen()
port = server.getsockname()[1]


def serve():
    conn, _ = server.accept()
    conn.sendall(b"SSH-2.0-FakeServer_1.0\r\n")
    conn.close()


threading.Thread(target=serve, daemon=True).start()

# 3. El escáner debe verlo abierto y leer el banner
_, found = scan("127.0.0.1", [port], timeout=1)
assert len(found) == 1 and found[0]["banner"] == "SSH-2.0-FakeServer_1.0", found
server.close()

# 4. En HTTP el banner útil es el encabezado Server, no la línea de estado
http = "HTTP/1.1 200 OK\nDate: hoy\nServer: Apache/2.4.7 (Ubuntu)"
assert summarize_banner(http) == "Apache/2.4.7 (Ubuntu)"

# 5. Reconoce producto y versión para buscar CVEs
assert detect_software("SSH-2.0-OpenSSH_6.6.1p1 Ubuntu")["version"] == "6.6.1"
assert detect_software("Apache/2.4.7 (Ubuntu)")["name"] == "Apache httpd"
assert detect_software("HTTP/1.1 200 OK") is None

# 6. El informe incluye riesgo general y ficha de cada puerto (con datos falsos, sin red)
fake = [{"port": 445, "service": "microsoft-ds", "banner": "", "software": None,
         "name": "SMB", "level": "CRÍTICO", "what": "x", "risks": "EternalBlue", "fix": "y"}]
path = os.path.join(tempfile.mkdtemp(), "r.md")
write_report("prueba", "10.0.0.5", 1, 0.1, fake, path)
text = open(path, encoding="utf-8").read()
assert "Riesgo general:** 🔴 CRÍTICO" in text and "EternalBlue" in text and "Red privada" in text

print("OK: todas las pruebas pasaron")
