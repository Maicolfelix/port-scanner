# 🔍 Port Scanner: escáner de puertos con informe de riesgos

Escáner de puertos **TCP y UDP** escrito en Python. Tiene tres técnicas de escaneo (connect, SYN *half-open* y UDP),
identifica el software y su versión, busca **vulnerabilidades conocidas (CVEs)** en la base de datos del NIST
y genera un **informe de riesgos** que explica cada puerto y cómo protegerlo.

El modo normal y el UDP usan solo la librería estándar. El modo SYN usa [Scapy](https://scapy.net/).

> ⚠️ **Uso ético:** escanea solo equipos propios o con autorización por escrito.
> Escanear sistemas ajenos puede ser ilegal (en Colombia: Ley 1273 de 2009).

## Ejemplo

```
$ python scanner.py scanme.nmap.org -p 21,22,23,80,443,445,3306,3389,9929,31337 --cves -r ejemplo_reporte.md
Escaneando scanme.nmap.org (10 puertos, TCP connect (handshake completo))...
Buscando CVEs de OpenSSH 6.6.1 en NVD...
Buscando CVEs de Apache httpd 2.4.7 en NVD...

PUERTO    SERVICIO      RIESGO    BANNER
22/tcp    ssh           MEDIO     SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
80/tcp    http          MEDIO     Apache/2.4.7 (Ubuntu)
9929/tcp  desconocido   MEDIO     (respuesta binaria)

3 abiertos de 10 en 45.33.32.156 - 3.26 s
Informe de riesgos: ejemplo_reporte.md
```

📄 **Informe generado:** [ejemplo_reporte.md](ejemplo_reporte.md). Incluye el riesgo general, una ficha por puerto
(qué es, riesgos, recomendación) y los CVEs más graves de cada versión detectada.

## Uso

```bash
python scanner.py <host> [-p PUERTOS] [--udp | --syn] [--cves] [-t TIMEOUT] [-w HILOS] [-o salida.json] [-r informe.md]

python scanner.py scanme.nmap.org -p 22,80 --cves          # TCP connect + CVEs
python scanner.py 192.168.1.1 -p 53,123,161,1900 --udp     # servicios UDP de un router propio
python scanner.py 192.168.1.10 -p 1-1024 --syn             # SYN half-open (como administrador)
```

| Opción | Qué hace | Default |
|---|---|---|
| `-p` | Puertos: `22,80` o rangos `1-1024` | `1-1024` |
| `--udp` | Escaneo UDP con sondas por protocolo | — |
| `--syn` | Escaneo SYN *half-open* (requiere admin, Scapy y Npcap) | — |
| `--cves` | Busca vulnerabilidades conocidas en NVD (requiere Internet) | desactivado |
| `-t` | Segundos de espera por puerto | `1` |
| `-w` | Hilos en paralelo | `200` |
| `-o` | Exporta resultados a JSON | — |
| `-r` | Nombre del informe de riesgos | `reporte_<host>_<fecha>.md` |

**Requisitos del modo SYN:** `pip install scapy` y ejecutar como administrador o root. En Windows también hay que instalar [Npcap](https://npcap.com/).

Pruebas: `python test_scanner.py`

## ¿Cómo funciona?

### Tres técnicas de escaneo

| Técnica | Cómo decide | Ventaja | Desventaja |
|---|---|---|---|
| **TCP connect** (default) | Completa el *three-way handshake* (SYN → SYN/ACK → ACK) | No necesita permisos especiales | La aplicación ve y registra la conexión |
| **TCP SYN** (`--syn`) | Envía solo el SYN. Si llega SYN/ACK, está abierto, y el sistema corta con RST sin completar la conexión | Más rápido; la aplicación nunca ve la conexión | Requiere paquetes crudos (admin); los IDS sí lo detectan |
| **UDP** (`--udp`) | Envía un mensaje válido del protocolo. Si hay respuesta está **abierto**; si llega "ICMP puerto inalcanzable" está **cerrado**; si hay silencio queda **abierto\|filtrado** | Encuentra servicios que TCP no ve (DNS, SNMP, NTP) | Lento y ambiguo: el silencio no dice nada |

**¿Por qué sondas por protocolo en UDP?** UDP no tiene handshake. Un servicio UDP ignora un paquete vacío, así que
para que responda hay que hablarle en su idioma. El escáner arma a mano, byte por byte, mensajes válidos de
DNS, NTP, NetBIOS, SNMP, SSDP y mDNS.

### El resto del proceso

1. **Concurrencia:** un `ThreadPoolExecutor` escanea cientos de puertos a la vez. Escanear es esperar a la red, así que los hilos reducen el tiempo de minutos a segundos.
2. **Banner grabbing:** primero escucha (SSH, FTP y SMTP se presentan solos); si no hay respuesta, envía un `HEAD` HTTP y lee el encabezado `Server`. En modo SYN, solo se conecta a los puertos que ya resultaron abiertos, como `nmap -sS -sV`.
3. **Detección de versión → CPE:** expresiones regulares reconocen productos (OpenSSH, Apache, nginx, IIS, vsFTPd, ProFTPD) y los traducen a su identificador **CPE**, el nombre estándar en la base de vulnerabilidades.
4. **Búsqueda de CVEs:** consulta la API pública de [NVD](https://nvd.nist.gov/) (NIST) y ordena las vulnerabilidades por severidad **CVSS** (0–10). Reintenta si choca con el límite de peticiones.
5. **Informe de riesgos:** cruza cada puerto con una base de conocimiento ([risks.py](risks.py), 36 servicios TCP y UDP) que explica qué es, qué ataques permite (EternalBlue, BlueKeep, Mirai, amplificación NTP…) y cómo mitigarlo. También indica la exposición según el tipo de IP (local, red privada o Internet).

## ¿Por qué importa en seguridad?

- **Atacantes:** el reconocimiento es la primera fase de un ataque (MITRE ATT&CK [T1046](https://attack.mitre.org/techniques/T1046/)). Un banner con una versión vieja lleva directo a buscar CVEs. Los servicios UDP como SNMP suelen olvidarse porque muchos escaneos solo revisan TCP.
- **Defensores:** auditar tu propia superficie de ataque, encontrar servicios expuestos por error (bases de datos, RDP, SNMP) y verificar reglas de firewall.

> **Privacidad:** los informes de escaneos reales (`reporte_*.md`) están en `.gitignore` porque revelan la superficie de ataque de tus equipos.

## Limitaciones conocidas

- Los CVEs se deducen de la versión del banner. Distribuciones como Ubuntu aplican parches de seguridad sin cambiar
  el número de versión (*backporting*), así que puede haber falsos positivos: hay que confirmarlos.
- Un servicio puede ocultar o falsificar su banner.
- **UDP:** muchos firewalls descartan los paquetes en silencio (scanme.nmap.org, por ejemplo), y Linux limita los mensajes
  ICMP a ~1 por segundo. Por eso es común ver muchos puertos *abierto|filtrado*. Las sondas DNS y NTP se validaron contra
  servidores públicos (8.8.8.8 y time.google.com).
- **SYN:** en Windows no funciona contra `127.0.0.1`, porque Npcap necesita su adaptador de loopback.

## Lo que aprendí

- Sockets TCP y UDP, y los estados de un puerto (abierto / cerrado / filtrado / abierto|filtrado)
- Construcción de paquetes a mano con Scapy y los flags TCP (SYN, ACK, RST)
- Formatos binarios de protocolos reales (DNS, NTP, SNMP/ASN.1, NetBIOS)
- Concurrencia con hilos en tareas limitadas por I/O
- Consumo de APIs REST, CPE, CVE y puntajes CVSS
- Riesgos concretos de los servicios más expuestos y cómo mitigarlos
- Ética, legalidad y privacidad en el escaneo de redes

## Mejoras implementadas

- [x] Búsqueda de CVEs por versión en NVD
- [x] Informe de riesgos por puerto
- [x] Escaneo UDP con sondas por protocolo (DNS, NTP, NetBIOS, SNMP, SSDP, mDNS)
- [x] Escaneo SYN (*half-open*) con Scapy
