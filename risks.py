"""
Base de conocimiento: qué es cada servicio y qué riesgo implica tenerlo expuesto.
Niveles: CRÍTICO > ALTO > MEDIO > BAJO
"""

LEVELS = ["BAJO", "MEDIO", "ALTO", "CRÍTICO"]
ICONS = {"BAJO": "🟢", "MEDIO": "🟡", "ALTO": "🟠", "CRÍTICO": "🔴"}

# puerto: (nombre, nivel, qué es, riesgos, recomendación)
PORTS = {
    21: ("FTP", "ALTO",
         "Transferencia de archivos. Protocolo de 1971, envía todo en texto plano.",
         "Usuario y contraseña viajan sin cifrar y se pueden capturar en la red. Muchos servidores permiten login anónimo. "
         "Versiones como vsFTPd 2.3.4 tienen puertas traseras conocidas.",
         "Reemplazar por SFTP (sobre SSH). Si es imprescindible, deshabilitar el acceso anónimo y usar FTPS."),
    22: ("SSH", "MEDIO",
         "Acceso remoto cifrado a la terminal del servidor.",
         "Blanco constante de ataques de fuerza bruta automatizados. Versiones viejas de OpenSSH tienen CVEs "
         "(ej. CVE-2024-6387 'regreSSHion', ejecución remota de código).",
         "Usar solo llaves (PasswordAuthentication no), deshabilitar login de root, instalar fail2ban y mantener OpenSSH actualizado."),
    23: ("Telnet", "CRÍTICO",
         "Acceso remoto a la terminal, predecesor de SSH, sin ningún cifrado.",
         "Todo, incluida la contraseña, viaja en texto plano. Es la puerta de entrada favorita de botnets como Mirai "
         "en routers y cámaras IoT con credenciales por defecto.",
         "Deshabilitarlo y usar SSH. No hay forma segura de exponer Telnet."),
    25: ("SMTP", "MEDIO",
         "Envío de correo entre servidores.",
         "Mal configurado funciona como 'open relay' que los spammers usan para enviar correo en tu nombre. "
         "Los comandos VRFY/EXPN permiten enumerar usuarios válidos.",
         "Bloquear el relay abierto, deshabilitar VRFY/EXPN y exigir STARTTLS."),
    53: ("DNS", "MEDIO",
         "Traduce nombres de dominio a direcciones IP.",
         "Un resolver abierto puede usarse en ataques DDoS de amplificación. Las transferencias de zona (AXFR) "
         "mal configuradas filtran todo el mapa interno de la red.",
         "Restringir la recursión a clientes internos y permitir AXFR solo a servidores secundarios."),
    69: ("TFTP", "ALTO",
         "Transferencia de archivos trivial (UDP), usada por routers, teléfonos IP y arranque por red.",
         "No tiene autenticación: cualquiera puede descargar (y a veces subir) archivos, como configuraciones "
         "de routers con contraseñas.",
         "Deshabilitarlo o limitarlo a la red de administración."),
    80: ("HTTP", "MEDIO",
         "Servidor web sin cifrado.",
         "El tráfico (incluidos formularios y cookies) viaja en texto plano. La aplicación web puede tener "
         "vulnerabilidades como inyección SQL o XSS, y el encabezado Server revela la versión del software.",
         "Redirigir todo a HTTPS, ocultar la versión del servidor y auditar la aplicación web."),
    110: ("POP3", "ALTO",
          "Descarga de correo electrónico, sin cifrado.",
          "Las credenciales del correo viajan en texto plano.",
          "Usar POP3S (puerto 995) y cerrar el 110."),
    111: ("RPCbind", "ALTO",
          "Directorio de servicios RPC de Unix (usado por NFS).",
          "Revela qué servicios internos corren y en qué puertos. Se ha usado para amplificación DDoS.",
          "Bloquearlo en el firewall para cualquier red externa."),
    123: ("NTP", "MEDIO",
          "Sincronización de la hora (UDP).",
          "Servidores viejos responden al comando 'monlist' con 600 direcciones: amplificación DDoS de hasta 500x "
          "(CVE-2013-5211). Alterar la hora rompe certificados y registros de auditoría.",
          "Actualizar ntpd, deshabilitar monlist y no responder consultas desde Internet."),
    135: ("MS-RPC", "ALTO",
          "Llamadas a procedimientos remotos de Windows.",
          "Históricamente explotado por gusanos (Blaster, CVE-2003-0352). Permite enumerar información del sistema.",
          "Nunca exponerlo a Internet; limitarlo a la red interna con el Firewall de Windows."),
    137: ("NetBIOS-NS", "ALTO",
          "Servicio de nombres de NetBIOS (UDP) de Windows.",
          "Revela el nombre del equipo, el dominio y usuarios conectados. Herramientas como Responder lo envenenan "
          "para robar hashes de contraseñas en la red local.",
          "Deshabilitar NetBIOS sobre TCP/IP y LLMNR si no se usan."),
    139: ("NetBIOS", "ALTO",
          "Compartición de archivos de Windows (versión antigua).",
          "Filtra nombres de equipos, usuarios y recursos compartidos. Base de ataques de relay de credenciales.",
          "Deshabilitar NetBIOS sobre TCP/IP si no se usa y bloquearlo hacia afuera."),
    143: ("IMAP", "ALTO",
          "Acceso al buzón de correo, sin cifrado.",
          "Las credenciales del correo viajan en texto plano.",
          "Usar IMAPS (puerto 993) y cerrar el 143."),
    161: ("SNMP", "ALTO",
          "Monitoreo y administración de equipos de red (UDP): routers, switches, impresoras.",
          "Muchos equipos dejan la comunidad por defecto 'public' (o 'private', que permite escribir): se lee la "
          "configuración completa del equipo, y a veces se puede cambiar. SNMP v1/v2c viaja sin cifrar.",
          "Usar SNMPv3 con autenticación y cifrado, cambiar las comunidades por defecto y limitar por IP."),
    443: ("HTTPS", "BAJO",
          "Servidor web cifrado con TLS.",
          "El cifrado protege el transporte, no la aplicación: puede tener las mismas fallas web que HTTP. "
          "Versiones viejas de TLS/SSL o certificados vencidos debilitan la protección.",
          "Usar solo TLS 1.2+, renovar certificados y auditar la aplicación."),
    445: ("SMB", "CRÍTICO",
          "Compartición de archivos e impresoras de Windows.",
          "Vector de los ataques más destructivos de la historia: EternalBlue (MS17-010) permitió a WannaCry y "
          "NotPetya propagarse solos por redes enteras. También se usa para fuerza bruta y robo de credenciales.",
          "Nunca exponerlo a Internet. Deshabilitar SMBv1, aplicar parches y exigir firma SMB."),
    500: ("IKE / IPsec VPN", "MEDIO",
          "Negociación de llaves para VPNs IPsec (UDP).",
          "Configuraciones con 'aggressive mode' y llave compartida (PSK) permiten capturar un hash y descifrar la "
          "llave por fuerza bruta offline (ike-scan + psk-crack).",
          "Deshabilitar aggressive mode, usar certificados en lugar de PSK y mantener el firmware al día."),
    993: ("IMAPS", "BAJO", "Correo IMAP cifrado con TLS.",
          "Riesgo principal: contraseñas débiles o robadas.",
          "Usar contraseñas fuertes y autenticación multifactor."),
    995: ("POP3S", "BAJO", "Correo POP3 cifrado con TLS.",
          "Riesgo principal: contraseñas débiles o robadas.",
          "Usar contraseñas fuertes y autenticación multifactor."),
    1433: ("MS SQL Server", "CRÍTICO",
           "Base de datos de Microsoft.",
           "Una base de datos expuesta es acceso directo a los datos. Objetivo constante de fuerza bruta contra la "
           "cuenta 'sa'; con acceso, xp_cmdshell permite ejecutar comandos en el sistema.",
           "Nunca exponerla a Internet: solo la aplicación debe conectarse. Deshabilitar 'sa' y xp_cmdshell."),
    1521: ("Oracle DB", "CRÍTICO", "Base de datos Oracle.",
           "Acceso directo a los datos; el listener puede filtrar información y tiene historial de CVEs.",
           "Restringir por firewall a los servidores de aplicación."),
    1900: ("SSDP / UPnP", "ALTO",
           "Descubrimiento automático de dispositivos (UDP): smart TVs, impresoras, routers.",
           "UPnP permite que cualquier programa de la red abra puertos en el router sin preguntar (lo usa el malware). "
           "Expuesto a Internet se usa para amplificación DDoS y revela modelo y versión del dispositivo.",
           "Deshabilitar UPnP en el router y bloquear el 1900 desde Internet."),
    2049: ("NFS", "ALTO", "Sistema de archivos en red de Unix.",
           "Exportaciones mal configuradas permiten montar y leer (o escribir) carpetas del servidor desde cualquier equipo.",
           "Exportar solo a IPs específicas y usar root_squash."),
    3306: ("MySQL / MariaDB", "CRÍTICO",
           "Base de datos relacional.",
           "Una base de datos expuesta es acceso directo a los datos. Objetivo de fuerza bruta contra 'root' y de "
           "campañas de ransomware que borran las tablas y piden rescate.",
           "Escuchar solo en 127.0.0.1 (bind-address) o en la red interna. Nunca exponerla a Internet."),
    3389: ("RDP", "CRÍTICO",
           "Escritorio remoto de Windows.",
           "Principal puerta de entrada de ransomware. Fuerza bruta masiva y vulnerabilidades críticas como "
           "BlueKeep (CVE-2019-0708), explotable sin contraseña.",
           "Nunca exponerlo directo a Internet: usar VPN, exigir NLA y MFA, y bloquear tras intentos fallidos."),
    5432: ("PostgreSQL", "CRÍTICO",
           "Base de datos relacional.",
           "Acceso directo a los datos. Con credenciales, COPY ... FROM PROGRAM permite ejecutar comandos en el servidor.",
           "listen_addresses = 'localhost' o red interna, y reglas estrictas en pg_hba.conf."),
    5353: ("mDNS", "BAJO",
           "DNS multicast (UDP): permite encontrar equipos como 'mi-pc.local' sin servidor DNS (Bonjour, AirPlay).",
           "Anuncia nombres de equipos y servicios a toda la red local. Expuesto a Internet sirve para amplificación DDoS.",
           "Normal en redes domésticas; bloquearlo hacia Internet en el firewall."),
    5900: ("VNC", "CRÍTICO",
           "Control remoto gráfico del escritorio.",
           "Muchas instalaciones no tienen contraseña o usan una débil (máx. 8 caracteres). El tráfico suele ir sin cifrar.",
           "Usarlo solo a través de un túnel SSH o VPN."),
    5985: ("WinRM (HTTP)", "ALTO", "Administración remota de Windows (PowerShell remoto).",
           "Con credenciales válidas da ejecución de comandos; muy usado para moverse lateralmente en una red.",
           "Limitarlo a equipos de administración y preferir el 5986 (HTTPS)."),
    6379: ("Redis", "CRÍTICO",
           "Base de datos en memoria.",
           "Por defecto no tiene contraseña. Un Redis expuesto permite leer todos los datos y hasta escribir llaves "
           "SSH en el servidor para tomar control.",
           "bind 127.0.0.1, activar protected-mode y requirepass."),
    8080: ("HTTP alternativo", "MEDIO",
           "Servidor web alternativo, usual en servidores de desarrollo, proxies y paneles (Tomcat, Jenkins).",
           "Suele exponer entornos de desarrollo o paneles de administración olvidados y menos protegidos.",
           "Cerrar si no se usa; si es un panel, ponerlo detrás de autenticación y VPN."),
    8443: ("HTTPS alternativo", "MEDIO",
           "Servidor web cifrado alternativo, común en paneles de administración.",
           "Paneles de administración expuestos son objetivo de fuerza bruta y exploits.",
           "Restringir el acceso por IP o VPN."),
    9200: ("Elasticsearch", "CRÍTICO", "Motor de búsqueda y análisis de datos.",
           "Sin autenticación por defecto en versiones antiguas: causa de muchas filtraciones masivas de datos.",
           "Activar la seguridad de Elastic y no exponerlo a Internet."),
    11211: ("Memcached", "ALTO", "Caché en memoria.",
            "Sin autenticación; usado en el mayor ataque DDoS de amplificación registrado (1.35 Tbps contra GitHub, 2018).",
            "Escuchar solo en localhost y deshabilitar UDP."),
    27017: ("MongoDB", "CRÍTICO", "Base de datos NoSQL.",
            "Versiones antiguas sin autenticación por defecto; miles de bases fueron borradas y pedido rescate.",
            "Activar autenticación y bindIp 127.0.0.1."),
}

UNKNOWN = ("Desconocido", "MEDIO",
           "Servicio no identificado en la base de conocimiento.",
           "Todo servicio que no sabes que está corriendo es un riesgo: puede ser software olvidado, "
           "sin parches, o incluso malware escuchando conexiones.",
           "Identificar el proceso (Windows: netstat -ano | findstr :PUERTO; Linux: ss -tlnp) y cerrarlo si no es necesario.")


def lookup(port):
    """Devuelve la ficha de riesgo de un puerto como diccionario."""
    name, level, what, risks, fix = PORTS.get(port, UNKNOWN)
    return {"name": name, "level": level, "what": what, "risks": risks, "fix": fix}
