# 🔍 Port Scanner — Escáner de puertos y servicios

Escáner de puertos TCP concurrente escrito en Python **sin dependencias externas**.
Detecta puertos abiertos, identifica el servicio y lee su *banner* (versión del software).

> ⚠️ **Uso ético:** escanea solo equipos propios o con autorización por escrito.
> Escanear sistemas ajenos puede ser ilegal (en Colombia: Ley 1273 de 2009).

## Ejemplo

```
$ python scanner.py scanme.nmap.org -p 22,80,443
Escaneando scanme.nmap.org (3 puertos)...

PUERTO  SERVICIO        BANNER
22      ssh             SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
80      http            HTTP/1.1 200 OK

2 abiertos de 3 en 45.33.32.156 - 1.29 s
```

## Uso

```bash
python scanner.py <host> [-p PUERTOS] [-t TIMEOUT] [-w HILOS] [-o salida.json]

python scanner.py scanme.nmap.org -p 22,80        # servidor que Nmap ofrece para pruebas
python scanner.py 192.168.1.10 -p 1-1024 -o reporte.json
```

| Opción | Qué hace | Default |
|---|---|---|
| `-p` | Puertos: `22,80` o rangos `1-1024` | `1-1024` |
| `-t` | Segundos de espera por puerto | `1` |
| `-w` | Hilos en paralelo | `200` |
| `-o` | Exporta resultados a JSON | — |

Pruebas: `python test_scanner.py`

## ¿Cómo funciona?

1. **TCP connect scan:** para cada puerto intenta el *three-way handshake* (SYN → SYN/ACK → ACK).
   Si se completa, el puerto está **abierto**; si responde RST, está **cerrado**; si no responde, está **filtrado** (firewall).
2. **Concurrencia:** un `ThreadPoolExecutor` escanea cientos de puertos a la vez. Escanear es esperar a la red, así que los hilos reducen el tiempo de minutos a segundos.
3. **Banner grabbing:** primero escucha (SSH, FTP y SMTP se presentan solos); si no hay respuesta, envía un `HEAD` HTTP para que los servidores web se identifiquen.
4. **Identificación de servicio:** usa la tabla IANA del sistema operativo, más una lista propia de puertos comunes.

## ¿Por qué importa en seguridad?

- **Atacantes:** el reconocimiento es la primera fase de un ataque (MITRE ATT&CK [T1046](https://attack.mitre.org/techniques/T1046/)). Un banner con una versión vieja lleva directo a buscar CVEs.
- **Defensores:** auditar tu propia superficie de ataque, encontrar servicios expuestos por error (bases de datos, RDP) y verificar reglas de firewall.

## Lo que aprendí

- Sockets TCP y estados de un puerto (abierto / cerrado / filtrado)
- Concurrencia con hilos en tareas limitadas por I/O
- Cómo distintos protocolos se identifican (o no) al conectarse
- Ética y legalidad del escaneo de redes

## Próximas mejoras

- [ ] Escaneo UDP
- [ ] Escaneo SYN ("half-open") con Scapy
- [ ] Coincidir versiones del banner contra la base de datos de CVEs (NVD)
