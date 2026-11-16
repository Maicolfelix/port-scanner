# 🔍 Port Scanner: escáner de puertos con informe de riesgos

Escáner de puertos TCP concurrente escrito en Python **sin dependencias externas**.
Detecta puertos abiertos, identifica el software y su versión, busca **vulnerabilidades conocidas (CVEs)**
en la base de datos del NIST y genera un **informe de riesgos** que explica cada puerto y cómo protegerlo.

> ⚠️ **Uso ético:** escanea solo equipos propios o con autorización por escrito.
> Escanear sistemas ajenos puede ser ilegal (en Colombia: Ley 1273 de 2009).

## Ejemplo

```
$ python scanner.py scanme.nmap.org -p 21,22,23,80,443,445,3306,3389,9929,31337 --cves -r ejemplo_reporte.md
Escaneando scanme.nmap.org (10 puertos)...
Buscando CVEs de OpenSSH 6.6.1 en NVD...
Buscando CVEs de Apache httpd 2.4.7 en NVD...

PUERTO  SERVICIO      RIESGO    BANNER
22      ssh           MEDIO     SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
80      http          MEDIO     Apache/2.4.7 (Ubuntu)
9929    desconocido   MEDIO     (respuesta binaria)

3 abiertos de 10 en 45.33.32.156 - 3.28 s
Informe de riesgos: ejemplo_reporte.md
```

📄 **Informe generado:** [ejemplo_reporte.md](ejemplo_reporte.md). Incluye el riesgo general, una ficha por puerto
(qué es, riesgos, recomendación) y los CVEs más graves de cada versión detectada (54 para OpenSSH 6.6.1 y 126 para Apache 2.4.7).

## Uso

```bash
python scanner.py <host> [-p PUERTOS] [-t TIMEOUT] [-w HILOS] [-o salida.json] [-r informe.md] [--cves]

python scanner.py scanme.nmap.org -p 22,80 --cves   # servidor que Nmap ofrece para pruebas
python scanner.py 192.168.1.10 -p 1-1024 -o reporte.json
```

| Opción | Qué hace | Default |
|---|---|---|
| `-p` | Puertos: `22,80` o rangos `1-1024` | `1-1024` |
| `-t` | Segundos de espera por puerto | `1` |
| `-w` | Hilos en paralelo | `200` |
| `-o` | Exporta resultados a JSON | — |
| `-r` | Nombre del informe de riesgos | `reporte_<host>_<fecha>.md` |
| `--cves` | Busca vulnerabilidades conocidas en NVD (requiere Internet) | desactivado |

Pruebas: `python test_scanner.py`

## ¿Cómo funciona?

1. **TCP connect scan:** para cada puerto intenta el *three-way handshake* (SYN → SYN/ACK → ACK).
   Si se completa, el puerto está **abierto**; si responde RST, está **cerrado**; si no responde, está **filtrado** (firewall).
2. **Concurrencia:** un `ThreadPoolExecutor` escanea cientos de puertos a la vez. Escanear es esperar a la red, así que los hilos reducen el tiempo de minutos a segundos.
3. **Banner grabbing:** primero escucha (SSH, FTP y SMTP se presentan solos); si no hay respuesta, envía un `HEAD` HTTP y lee el encabezado `Server`, que revela el software web y su versión.
4. **Detección de versión → CPE:** expresiones regulares reconocen productos (OpenSSH, Apache, nginx, IIS, vsFTPd, ProFTPD) y los traducen a su identificador **CPE**, el nombre estándar que usa la base de vulnerabilidades.
5. **Búsqueda de CVEs:** consulta la API pública de [NVD](https://nvd.nist.gov/) (NIST) y ordena las vulnerabilidades por severidad **CVSS** (0–10). Reintenta si choca con el límite de peticiones.
6. **Informe de riesgos:** cruza cada puerto con una base de conocimiento ([risks.py](risks.py), 29 servicios) que explica qué es, qué ataques permite (EternalBlue, BlueKeep, Mirai…) y cómo mitigarlo. También indica la exposición según el tipo de IP (local, red privada o Internet).

## ¿Por qué importa en seguridad?

- **Atacantes:** el reconocimiento es la primera fase de un ataque (MITRE ATT&CK [T1046](https://attack.mitre.org/techniques/T1046/)). Un banner con una versión vieja lleva directo a buscar CVEs.
- **Defensores:** auditar tu propia superficie de ataque, encontrar servicios expuestos por error (bases de datos, RDP) y verificar reglas de firewall.

> **Privacidad:** los informes de escaneos reales (`reporte_*.md`) están en `.gitignore` porque revelan la superficie de ataque de tus equipos.

## Limitaciones conocidas

- Los CVEs se deducen de la versión del banner. Distribuciones como Ubuntu aplican parches de seguridad sin cambiar
  el número de versión (*backporting*), así que puede haber falsos positivos: hay que confirmarlos.
- Un servicio puede ocultar o falsificar su banner.
- Solo TCP. Un escaneo UDP fiable exige sondas específicas por protocolo, y un escaneo SYN exige privilegios de administrador y Npcap.

## Lo que aprendí

- Sockets TCP y estados de un puerto (abierto / cerrado / filtrado)
- Concurrencia con hilos en tareas limitadas por I/O
- Cómo distintos protocolos se identifican (o no) al conectarse
- Consumo de APIs REST, CPE, CVE y puntajes CVSS
- Riesgos concretos de los servicios más expuestos y cómo mitigarlos
- Ética, legalidad y privacidad en el escaneo de redes

## Próximas mejoras

- [x] Coincidir versiones del banner contra la base de datos de CVEs (NVD)
- [x] Informe de riesgos por puerto
- [ ] Escaneo UDP con sondas por protocolo (DNS, NTP, SNMP)
- [ ] Escaneo SYN ("half-open") con Scapy
