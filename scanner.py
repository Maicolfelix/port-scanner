"""
Escáner de puertos TCP concurrente con detección de servicios, búsqueda de CVEs
e informe de riesgos. Solo usa la librería estándar de Python.

USO ÉTICO: escanea únicamente equipos propios o con autorización por escrito.
"""
import argparse
import ipaddress
import json
import re
import socket
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from risks import ICONS, LEVELS, lookup

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Software que sabemos reconocer en un banner: (regex de versión, nombre, prefijo CPE)
# CPE es el "nombre oficial" de un producto en la base de vulnerabilidades NVD.
SOFTWARE = [
    (r"OpenSSH[_-](\d+\.\d+(?:\.\d+)?)", "OpenSSH", "cpe:2.3:a:openbsd:openssh"),
    (r"Apache/(\d+\.\d+\.\d+)", "Apache httpd", "cpe:2.3:a:apache:http_server"),
    (r"nginx/(\d+\.\d+\.\d+)", "nginx", "cpe:2.3:a:f5:nginx"),
    (r"Microsoft-IIS/(\d+\.\d+)", "Microsoft IIS", "cpe:2.3:a:microsoft:internet_information_services"),
    (r"vsFTPd (\d+\.\d+\.\d+)", "vsFTPd", "cpe:2.3:a:vsftpd_project:vsftpd"),
    (r"ProFTPD (\d+\.\d+\.\d+)", "ProFTPD", "cpe:2.3:a:proftpd:proftpd"),
]

# Puertos comunes que la tabla del sistema (sobre todo en Windows) no siempre trae.
COMMON_PORTS = {3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
                6379: "redis", 8080: "http-alt", 8443: "https-alt", 27017: "mongodb"}


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
    """Lee lo que el servicio dice de sí mismo (su 'banner'). Devuelve el texto completo."""
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
    # Algunos protocolos (MySQL, RDP...) responden en binario, no en texto.
    readable = sum(32 <= b < 127 or b in (9, 10, 13) for b in data)
    if data and readable / len(data) < 0.9:
        return "(respuesta binaria)"
    return "".join(c for c in data.decode("ascii", errors="ignore") if c.isprintable() or c == "\n").strip()


def summarize_banner(text):
    """Línea más útil del banner: en HTTP el encabezado 'Server' dice el software y versión."""
    lines = text.splitlines()
    for line in lines:
        if line.lower().startswith("server:"):
            return line.split(":", 1)[1].strip()[:100]
    return lines[0][:100] if lines else ""


def detect_software(banner):
    """Reconoce producto y versión en el banner, ej. 'OpenSSH_6.6.1p1' -> OpenSSH 6.6.1."""
    for pattern, name, cpe in SOFTWARE:
        match = re.search(pattern, banner)
        if match:
            return {"name": name, "version": match.group(1), "cpe": cpe}
    return None


def cvss_score(cve):
    """Puntaje de severidad CVSS (0-10). Prefiere la versión más nueva del estándar."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if cve["metrics"].get(key):
            return cve["metrics"][key][0]["cvssData"]["baseScore"]
    return 0.0


def find_cves(software, top=5):
    """Consulta en NVD (base pública del NIST) las vulnerabilidades conocidas de esa versión."""
    query = urllib.parse.urlencode({
        "virtualMatchString": f"{software['cpe']}:{software['version']}",
        "resultsPerPage": 2000,
    })
    for attempt in range(3):
        try:
            with urllib.request.urlopen(f"{NVD_API}?{query}", timeout=30) as resp:
                data = json.load(resp)
            break
        except (OSError, ValueError):
            # NVD sin API key permite ~5 consultas cada 30 s: esperamos y reintentamos.
            time.sleep(7)
    else:
        return None
    cves = sorted((v["cve"] for v in data["vulnerabilities"]), key=cvss_score, reverse=True)
    return {"total": data["totalResults"],
            "top": [{"id": c["id"], "score": cvss_score(c),
                     "summary": c["descriptions"][0]["value"][:160]} for c in cves[:top]]}


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
        # Solo los puertos abiertos llegan aquí: les damos más paciencia para presentarse.
        sock.settimeout(max(timeout, 3.0))
        banner = summarize_banner(grab_banner(sock))
        return {"port": port, "service": service_name(port), "banner": banner,
                "software": detect_software(banner), **lookup(port)}


def scan(host, ports, timeout=1.0, workers=200):
    ip = socket.gethostbyname(host)  # resuelve el nombre DNS a una IP
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda p: scan_port(ip, p, timeout), ports)
    return ip, [r for r in results if r]


def exposure(ip):
    """Desde dónde se puede llegar a estos puertos, según el tipo de IP."""
    addr = ipaddress.ip_address(ip)
    if addr.is_loopback:
        return "Local (127.x): solo se ve desde este mismo equipo, salvo que el firewall también los exponga a la red."
    if addr.is_private:
        return "Red privada: visible para cualquier dispositivo de la misma red (Wi-Fi, oficina)."
    return "IP pública: visible para todo Internet. Bots escanean Internet completo en minutos."


def write_report(host, ip, scanned, elapsed, results, path):
    """Genera el informe en Markdown: qué es cada puerto, sus riesgos y cómo mitigarlos."""
    overall = max((r["level"] for r in results), key=LEVELS.index, default="BAJO")
    out = [
        f"# Informe de escaneo: {host}", "",
        f"- **Fecha:** {datetime.now():%Y-%m-%d %H:%M}",
        f"- **IP:** {ip}",
        f"- **Exposición:** {exposure(ip)}",
        f"- **Puertos escaneados:** {scanned} en {elapsed:.2f} s",
        f"- **Puertos abiertos:** {len(results)}",
        f"- **Riesgo general:** {ICONS[overall]} {overall}", "",
        "## Resumen", "",
        "| Puerto | Servicio | Software detectado | Riesgo | CVEs conocidos |",
        "|---|---|---|---|---|",
    ]
    for r in results:
        sw = f"{r['software']['name']} {r['software']['version']}" if r["software"] else "-"
        cves = r.get("cves")
        out.append(f"| {r['port']}/tcp | {r['name']} | {sw} | {ICONS[r['level']]} {r['level']} | "
                   f"{cves['total'] if cves else '-'} |")

    out += ["", "## Detalle por puerto"]
    for r in sorted(results, key=lambda r: LEVELS.index(r["level"]), reverse=True):
        banner = r["banner"].replace("`", "'")  # una comilla invertida rompería el formato Markdown
        out += ["", f"### {ICONS[r['level']]} {r['port']}/tcp: {r['name']} ({r['level']})", "",
                f"- **Qué es:** {r['what']}",
                f"- **Banner:** `{banner}`" if banner else "- **Banner:** (el servicio no se identificó)",
                f"- **Riesgos:** {r['risks']}",
                f"- **Recomendación:** {r['fix']}"]
        cves = r.get("cves")
        if cves:
            sw = r["software"]
            out += [f"- **CVEs conocidos para {sw['name']} {sw['version']}:** {cves['total']} en NVD. Los más graves:", ""]
            out += [f"  - [{c['id']}](https://nvd.nist.gov/vuln/detail/{c['id']}) (CVSS {c['score']}): {c['summary']}"
                    for c in cves["top"]]

    out += ["", "## Notas", "",
            "- Un puerto abierto no es una vulnerabilidad por sí solo: el riesgo depende de si debe estar expuesto y de cómo está configurado.",
            "- Los CVEs se deducen de la versión del banner. Distribuciones como Ubuntu aplican parches sin cambiar "
            "el número de versión, así que pueden ser falsos positivos: confírmalos antes de reportarlos.",
            "- Regla general: cierra todo lo que no necesites y limita por firewall lo que sí."]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")


def main():
    parser = argparse.ArgumentParser(description="Escáner de puertos TCP con detección de servicios e informe de riesgos")
    parser.add_argument("host", help="IP o dominio objetivo (solo con autorización)")
    parser.add_argument("-p", "--ports", default="1-1024", help="ej: 22,80,443 o 1-1024 (default: 1-1024)")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="segundos por puerto (default: 1)")
    parser.add_argument("-w", "--workers", type=int, default=200, help="hilos en paralelo (default: 200)")
    parser.add_argument("-o", "--output", help="guardar resultados en un archivo JSON")
    parser.add_argument("-r", "--report", help="nombre del informe (default: reporte_<host>_<fecha>.md)")
    parser.add_argument("--cves", action="store_true", help="buscar vulnerabilidades conocidas en NVD (requiere Internet)")
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    print(f"Escaneando {args.host} ({len(ports)} puertos)...")
    start = time.perf_counter()
    ip, open_ports = scan(args.host, ports, args.timeout, args.workers)
    elapsed = time.perf_counter() - start

    if args.cves:
        cache = {}  # misma versión en varios puertos = una sola consulta
        for r in open_ports:
            if r["software"]:
                key = (r["software"]["cpe"], r["software"]["version"])
                if key not in cache:
                    print(f"Buscando CVEs de {r['software']['name']} {r['software']['version']} en NVD...")
                    cache[key] = find_cves(r["software"])
                r["cves"] = cache[key]

    print(f"\n{'PUERTO':<8}{'SERVICIO':<14}{'RIESGO':<10}BANNER")
    for r in open_ports:
        print(f"{r['port']:<8}{r['service']:<14}{r['level']:<10}{r['banner']}")
    print(f"\n{len(open_ports)} abiertos de {len(ports)} en {ip} - {elapsed:.2f} s")

    safe_host = re.sub(r"[^\w.-]", "_", args.host)  # sin caracteres inválidos para un nombre de archivo
    report = args.report or f"reporte_{safe_host}_{datetime.now():%Y%m%d-%H%M%S}.md"
    write_report(args.host, ip, len(ports), elapsed, open_ports, report)
    print(f"Informe de riesgos: {report}")

    if args.output:
        data = {"host": args.host, "ip": ip, "scanned": len(ports),
                "seconds": round(elapsed, 2), "open": open_ports}
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"Resultados guardados en {args.output}")


if __name__ == "__main__":
    main()
