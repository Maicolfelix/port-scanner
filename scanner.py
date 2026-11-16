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
    return to_text(data)


def to_text(data):
    """Convierte la respuesta en texto legible, o avisa si es binaria."""
    # Algunos protocolos (MySQL, RDP, DNS...) responden en binario, no en texto.
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


def service_name(port, proto="tcp"):
    """Nombre 'oficial' del puerto según la tabla IANA del sistema."""
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return COMMON_PORTS.get(port, "desconocido")


def scan_port(host, port, timeout):
    """TCP connect: devuelve un dict si el puerto está abierto, o None si está cerrado/filtrado."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        # connect_ex devuelve 0 si el 'three-way handshake' TCP se completó.
        if sock.connect_ex((host, port)) != 0:
            return None
        # Solo los puertos abiertos llegan aquí: les damos más paciencia para presentarse.
        sock.settimeout(max(timeout, 3.0))
        banner = summarize_banner(grab_banner(sock))
        return {"port": port, "proto": "tcp", "state": "abierto", "service": service_name(port),
                "banner": banner, "software": detect_software(banner), **lookup(port)}


# UDP no tiene handshake: un servicio solo responde si le hablas en SU protocolo.
# Por eso cada puerto conocido recibe un mensaje válido de ese protocolo.
DNS_QUERY = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"  # cabecera: 1 pregunta
             b"\x07example\x03com\x00\x00\x01\x00\x01")           # ¿IP (A) de example.com?
UDP_PROBES = {
    53: DNS_QUERY,
    5353: (b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"    # mDNS: mismo formato que DNS, pero
           b"\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01"),  # pregunta qué servicios hay (.local)
    123: b"\x1b" + b"\x00" * 47,                                   # NTP: pedir la hora (cliente v3)
    137: b"\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00"     # NetBIOS: pedir tabla de nombres
         b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01",
    161: bytes.fromhex("302602010004067075626c6963a019020101020100020100"
                       "300e300c06082b060102010101000500"),       # SNMP v1: sysDescr con comunidad 'public'
    1900: b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"  # SSDP/UPnP: descubrir dispositivos
          b"MAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n",
}


def udp_scan_port(host, port, timeout):
    """UDP: 'abierto' si responde, None si está cerrado, 'abierto|filtrado' si hay silencio."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        # connect() en UDP no envía nada: solo hace que el sistema nos avise de errores ICMP.
        sock.connect((host, port))
        try:
            sock.send(UDP_PROBES.get(port, b""))
            data = sock.recv(1024)
        except socket.timeout:
            # Silencio: o el servicio ignoró el mensaje, o un firewall lo descartó. No se puede saber.
            data = None
        except ConnectionError:
            # El equipo respondió "ICMP puerto inalcanzable": el puerto está cerrado.
            return None
    banner = summarize_banner(to_text(data)) if data else ""
    return {"port": port, "proto": "udp", "state": "abierto" if data is not None else "abierto|filtrado",
            "service": service_name(port, "udp"), "banner": banner, "software": None, **lookup(port)}


def is_syn_ack(packet):
    """En la respuesta TCP, los flags SYN (0x02) y ACK (0x10) juntos significan 'puerto abierto'."""
    from scapy.all import TCP
    return packet.haslayer(TCP) and packet[TCP].flags & 0x12 == 0x12


def syn_open_ports(ip, ports, timeout):
    """Escaneo SYN ('half-open'): envía solo el SYN y nunca completa el handshake."""
    try:
        from scapy.all import IP, TCP, conf, sr
    except ImportError:
        raise SystemExit("El escaneo SYN necesita Scapy: pip install scapy (y Npcap en Windows)")
    conf.verb = 0
    try:
        # Paquetes hechos a mano: Scapy arma la cabecera IP y TCP con el flag S (SYN).
        answered, _ = sr(IP(dst=ip) / TCP(dport=ports, flags="S"), timeout=max(timeout, 2), retry=1)
    except (OSError, RuntimeError, PermissionError) as e:
        raise SystemExit(f"No se pudieron enviar paquetes crudos ({e}). "
                         "Ejecuta como administrador y, en Windows, instala Npcap.")
    # El sistema operativo responde RST solo al SYN/ACK (no abrió esa conexión), cerrándola a medias.
    return sorted({received[TCP].sport for _, received in answered if is_syn_ack(received)})


def scan(host, ports, timeout=1.0, workers=200, mode="connect"):
    """mode: 'connect' (TCP completo), 'syn' (TCP half-open, requiere admin) o 'udp'."""
    ip = socket.gethostbyname(host)  # resuelve el nombre DNS a una IP
    if mode == "syn":
        # Tras el SYN, se conecta solo a los abiertos para leer su banner (como nmap -sS -sV).
        ports = syn_open_ports(ip, ports, timeout)
    probe = udp_scan_port if mode == "udp" else scan_port
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda p: probe(ip, p, timeout), ports)
    return ip, [r for r in results if r]


def exposure(ip):
    """Desde dónde se puede llegar a estos puertos, según el tipo de IP."""
    addr = ipaddress.ip_address(ip)
    if addr.is_loopback:
        return "Local (127.x): solo se ve desde este mismo equipo, salvo que el firewall también los exponga a la red."
    if addr.is_private:
        return "Red privada: visible para cualquier dispositivo de la misma red (Wi-Fi, oficina)."
    return "IP pública: visible para todo Internet. Bots escanean Internet completo en minutos."


def write_report(host, ip, scanned, elapsed, results, path, mode="connect", silent=0):
    """Genera el informe en Markdown: qué es cada puerto, sus riesgos y cómo mitigarlos."""
    overall = max((r["level"] for r in results), key=LEVELS.index, default="BAJO")
    out = [
        f"# Informe de escaneo: {host}", "",
        f"- **Fecha:** {datetime.now():%Y-%m-%d %H:%M}",
        f"- **IP:** {ip}",
        f"- **Exposición:** {exposure(ip)}",
        f"- **Tipo de escaneo:** {SCAN_TYPES[mode]}",
        f"- **Puertos escaneados:** {scanned} en {elapsed:.2f} s",
        f"- **Puertos abiertos:** {len(results)}"
        + (f" (y {silent} UDP sin respuesta: abierto|filtrado)" if silent else ""),
        f"- **Riesgo general:** {ICONS[overall]} {overall}", "",
        "## Resumen", "",
        "| Puerto | Servicio | Software detectado | Riesgo | CVEs conocidos |",
        "|---|---|---|---|---|",
    ]
    for r in results:
        sw = f"{r['software']['name']} {r['software']['version']}" if r["software"] else "-"
        cves = r.get("cves")
        out.append(f"| {r['port']}/{r['proto']} | {r['name']} | {sw} | {ICONS[r['level']]} {r['level']} | "
                   f"{cves['total'] if cves else '-'} |")

    if not results:
        out.append("| - | No se encontraron puertos abiertos | - | - | - |")

    out += ["", "## Detalle por puerto"]
    for r in sorted(results, key=lambda r: LEVELS.index(r["level"]), reverse=True):
        banner = r["banner"].replace("`", "'")  # una comilla invertida rompería el formato Markdown
        out += ["", f"### {ICONS[r['level']]} {r['port']}/{r['proto']}: {r['name']} ({r['level']})", "",
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


SCAN_TYPES = {
    "connect": "TCP connect (handshake completo)",
    "syn": "TCP SYN / half-open (sin completar el handshake)",
    "udp": "UDP con sondas por protocolo",
}


def main():
    parser = argparse.ArgumentParser(description="Escáner de puertos TCP/UDP con detección de servicios e informe de riesgos")
    parser.add_argument("host", help="IP o dominio objetivo (solo con autorización)")
    parser.add_argument("-p", "--ports", default="1-1024", help="ej: 22,80,443 o 1-1024 (default: 1-1024)")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="segundos por puerto (default: 1)")
    parser.add_argument("-w", "--workers", type=int, default=200, help="hilos en paralelo (default: 200)")
    parser.add_argument("-o", "--output", help="guardar resultados en un archivo JSON")
    parser.add_argument("-r", "--report", help="nombre del informe (default: reporte_<host>_<fecha>.md)")
    parser.add_argument("--cves", action="store_true", help="buscar vulnerabilidades conocidas en NVD (requiere Internet)")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--udp", action="store_true", help="escaneo UDP (DNS, NTP, SNMP, NetBIOS, SSDP...)")
    mode.add_argument("--syn", action="store_true", help="escaneo SYN half-open (requiere admin, Scapy y Npcap)")
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    scan_mode = "udp" if args.udp else "syn" if args.syn else "connect"
    print(f"Escaneando {args.host} ({len(ports)} puertos, {SCAN_TYPES[scan_mode]})...")
    start = time.perf_counter()
    ip, results = scan(args.host, ports, args.timeout, args.workers, scan_mode)
    elapsed = time.perf_counter() - start
    open_ports = [r for r in results if r["state"] == "abierto"]
    silent = len(results) - len(open_ports)  # solo en UDP: puertos que no respondieron

    if args.cves:
        cache = {}  # misma versión en varios puertos = una sola consulta
        for r in open_ports:
            if r["software"]:
                key = (r["software"]["cpe"], r["software"]["version"])
                if key not in cache:
                    print(f"Buscando CVEs de {r['software']['name']} {r['software']['version']} en NVD...")
                    cache[key] = find_cves(r["software"])
                r["cves"] = cache[key]

    print(f"\n{'PUERTO':<10}{'SERVICIO':<14}{'RIESGO':<10}BANNER")
    for r in open_ports:
        port = f"{r['port']}/{r['proto']}"
        print(f"{port:<10}{r['service']:<14}{r['level']:<10}{r['banner']}")
    print(f"\n{len(open_ports)} abiertos de {len(ports)} en {ip} - {elapsed:.2f} s")
    if silent:
        print(f"{silent} puertos UDP no respondieron (abierto|filtrado: no se puede distinguir)")

    safe_host = re.sub(r"[^\w.-]", "_", args.host)  # sin caracteres inválidos para un nombre de archivo
    report = args.report or f"reporte_{safe_host}_{datetime.now():%Y%m%d-%H%M%S}.md"
    write_report(args.host, ip, len(ports), elapsed, open_ports, report, scan_mode, silent)
    print(f"Informe de riesgos: {report}")

    if args.output:
        data = {"host": args.host, "ip": ip, "scanned": len(ports),
                "seconds": round(elapsed, 2), "open": open_ports}
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"Resultados guardados en {args.output}")


if __name__ == "__main__":
    main()
