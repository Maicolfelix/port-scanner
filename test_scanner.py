"""Pruebas: python test_scanner.py"""
import os
import socket
import tempfile
import threading

from scanner import detect_software, parse_ports, scan, summarize_banner, udp_scan_port, write_report

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
fake = [{"port": 445, "proto": "tcp", "state": "abierto", "service": "microsoft-ds", "banner": "",
         "software": None, "name": "SMB", "level": "CRÍTICO", "what": "x", "risks": "EternalBlue", "fix": "y"}]
path = os.path.join(tempfile.mkdtemp(), "r.md")
write_report("prueba", "10.0.0.5", 1, 0.1, fake, path)
text = open(path, encoding="utf-8").read()
assert "Riesgo general:** 🔴 CRÍTICO" in text and "EternalBlue" in text and "Red privada" in text
assert "445/tcp" in text

# 7. UDP abierto: un servidor DNS falso que responde
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.bind(("127.0.0.1", 0))
udp_port = udp.getsockname()[1]


def answer():
    data, addr = udp.recvfrom(1024)
    udp.sendto(b"\x12\x34\x81\x80" + data[4:], addr)  # devuelve la consulta marcada como respuesta


threading.Thread(target=answer, daemon=True).start()
r = udp_scan_port("127.0.0.1", udp_port, 1)
assert r and r["state"] == "abierto" and r["proto"] == "udp", r

# 8. UDP en silencio: un servicio que recibe pero nunca responde = abierto|filtrado
r = udp_scan_port("127.0.0.1", udp_port, 0.5)  # el hilo ya terminó: nadie contesta
assert r and r["state"] == "abierto|filtrado", r
udp.close()

# 9. UDP cerrado: nadie escucha, el sistema responde 'ICMP puerto inalcanzable'
assert udp_scan_port("127.0.0.1", udp_port, 1) is None

# 10. Escaneo SYN: clasificar respuestas (solo si Scapy está instalado)
try:
    from scapy.all import IP, TCP
    from scanner import is_syn_ack
    assert is_syn_ack(IP() / TCP(flags="SA"))       # SYN/ACK = abierto
    assert not is_syn_ack(IP() / TCP(flags="RA"))   # RST/ACK = cerrado
    print("SYN: clasificación verificada")
except ImportError:
    print("SYN: Scapy no instalado, prueba omitida")

print("OK: todas las pruebas pasaron")
