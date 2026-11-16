"""Pruebas: python test_scanner.py"""
import socket
import threading

from scanner import parse_ports, scan

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

print("OK: todas las pruebas pasaron")
