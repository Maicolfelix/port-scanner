"""
Escáner de puertos TCP concurrente con detección de servicios (banner grabbing).
Solo usa la librería estándar de Python.

USO ÉTICO: escanea únicamente equipos propios o con autorización por escrito.
"""
import argparse
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor


def parse_ports(spec):
    """Convierte '22,80,8000-8010' en una lista ordenada de puertos sin repetir."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.update(range(start, end + 1))
        elif part:
            ports.add(int(part))
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("Los puertos deben estar entre 1 y 65535")
    return sorted(ports)


def grab_banner(sock):
    """Intenta leer lo que el servicio dice de sí mismo (su 'banner')."""
    try:
        try:
            # Servicios como SSH, FTP o SMTP hablan primero: basta con escuchar.
            data = sock.recv(1024)
        except socket.timeout:
            data = b""
        if not data:
            # Servicios como HTTP esperan a que el cliente hable primero.
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = sock.recv(1024)
    except OSError:
        return ""
    # Algunos protocolos (MySQL, RDP...) responden en binario: dejamos solo texto legible.
    text = "".join(c for c in data.decode("ascii", errors="ignore") if c.isprintable() or c == "\n")
    lines = text.strip().splitlines()
    return lines[0][:100] if lines else ""


# Puertos comunes que la tabla del sistema (sobre todo en Windows) no siempre trae.
COMMON_PORTS = {3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
                6379: "redis", 8080: "http-alt", 8443: "https-alt", 27017: "mongodb"}


def service_name(port):
    """Nombre 'oficial' del puerto según la tabla IANA del sistema."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return COMMON_PORTS.get(port, "desconocido")


def scan_port(host, port, timeout):
    """Devuelve un dict si el puerto está abierto, o None si está cerrado/filtrado."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        # connect_ex devuelve 0 si el 'three-way handshake' TCP se completó.
        if sock.connect_ex((host, port)) != 0:
            return None
        return {"port": port, "service": service_name(port), "banner": grab_banner(sock)}


def scan(host, ports, timeout=1.0, workers=200):
    ip = socket.gethostbyname(host)  # resuelve el nombre DNS a una IP
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda p: scan_port(ip, p, timeout), ports)
    return ip, [r for r in results if r]


def main():
    parser = argparse.ArgumentParser(description="Escáner de puertos TCP con detección de servicios")
    parser.add_argument("host", help="IP o dominio objetivo (solo con autorización)")
    parser.add_argument("-p", "--ports", default="1-1024", help="ej: 22,80,443 o 1-1024 (default: 1-1024)")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="segundos por puerto (default: 1)")
    parser.add_argument("-w", "--workers", type=int, default=200, help="hilos en paralelo (default: 200)")
    parser.add_argument("-o", "--output", help="guardar resultados en un archivo JSON")
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    print(f"Escaneando {args.host} ({len(ports)} puertos)...")
    start = time.perf_counter()
    ip, open_ports = scan(args.host, ports, args.timeout, args.workers)
    elapsed = time.perf_counter() - start

    print(f"\n{'PUERTO':<8}{'SERVICIO':<16}BANNER")
    for r in open_ports:
        print(f"{r['port']:<8}{r['service']:<16}{r['banner']}")
    print(f"\n{len(open_ports)} abiertos de {len(ports)} en {ip} - {elapsed:.2f} s")

    if args.output:
        report = {"host": args.host, "ip": ip, "scanned": len(ports),
                  "seconds": round(elapsed, 2), "open": open_ports}
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"Resultados guardados en {args.output}")


if __name__ == "__main__":
    main()
