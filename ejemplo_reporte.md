# Informe de escaneo: scanme.nmap.org

- **Fecha:** 2026-11-15 20:36
- **IP:** 45.33.32.156
- **Exposición:** IP pública: visible para todo Internet. Bots escanean Internet completo en minutos.
- **Tipo de escaneo:** TCP connect (handshake completo)
- **Puertos escaneados:** 10 en 3.26 s
- **Puertos abiertos:** 3
- **Riesgo general:** 🟡 MEDIO

## Resumen

| Puerto | Servicio | Software detectado | Riesgo | CVEs conocidos |
|---|---|---|---|---|
| 22/tcp | SSH | OpenSSH 6.6.1 | 🟡 MEDIO | 54 |
| 80/tcp | HTTP | Apache httpd 2.4.7 | 🟡 MEDIO | 126 |
| 9929/tcp | Desconocido | - | 🟡 MEDIO | - |

## Detalle por puerto

### 🟡 22/tcp: SSH (MEDIO)

- **Qué es:** Acceso remoto cifrado a la terminal del servidor.
- **Banner:** `SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13`
- **Riesgos:** Blanco constante de ataques de fuerza bruta automatizados. Versiones viejas de OpenSSH tienen CVEs (ej. CVE-2024-6387 'regreSSHion', ejecución remota de código).
- **Recomendación:** Usar solo llaves (PasswordAuthentication no), deshabilitar login de root, instalar fail2ban y mantener OpenSSH actualizado.
- **CVEs conocidos para OpenSSH 6.6.1:** 54 en NVD. Los más graves:

  - [CVE-2016-1908](https://nvd.nist.gov/vuln/detail/CVE-2016-1908) (CVSS 9.8): The client in OpenSSH before 7.2 mishandles failed cookie generation for untrusted X11 forwarding and relies on the local X11 server for access-control decision
  - [CVE-2023-38408](https://nvd.nist.gov/vuln/detail/CVE-2023-38408) (CVSS 9.8): The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 has an insufficiently trustworthy search path, leading to remote code execution if an agent is forwarde
  - [CVE-2015-5600](https://nvd.nist.gov/vuln/detail/CVE-2015-5600) (CVSS 8.1): The kbdint_next_device function in auth2-chall.c in sshd in OpenSSH through 6.9 does not properly restrict the processing of keyboard-interactive devices within
  - [CVE-2026-123158](https://nvd.nist.gov/vuln/detail/CVE-2026-123158) (CVSS 8.1): sshd in OpenSSH before 10.6p2 on Linux, when musl libc is used without PAM, lacks a workaround for a password authentication bypass (related to misinterpretatio
  - [CVE-2015-8325](https://nvd.nist.gov/vuln/detail/CVE-2015-8325) (CVSS 7.8): The do_setup_env function in session.c in sshd in OpenSSH through 7.2p2, when the UseLogin feature is enabled and PAM is configured to read .pam_environment fil

### 🟡 80/tcp: HTTP (MEDIO)

- **Qué es:** Servidor web sin cifrado.
- **Banner:** `Apache/2.4.7 (Ubuntu)`
- **Riesgos:** El tráfico (incluidos formularios y cookies) viaja en texto plano. La aplicación web puede tener vulnerabilidades como inyección SQL o XSS, y el encabezado Server revela la versión del software.
- **Recomendación:** Redirigir todo a HTTPS, ocultar la versión del servidor y auditar la aplicación web.
- **CVEs conocidos para Apache httpd 2.4.7:** 126 en NVD. Los más graves:

  - [CVE-2017-3167](https://nvd.nist.gov/vuln/detail/CVE-2017-3167) (CVSS 9.8): In Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26, use of the ap_get_basic_auth_pw() by third-party modules outside of the authentication phase may le
  - [CVE-2017-7679](https://nvd.nist.gov/vuln/detail/CVE-2017-7679) (CVSS 9.8): In Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26, mod_mime can read one byte past the end of a buffer when sending a malicious Content-Type response 
  - [CVE-2018-1312](https://nvd.nist.gov/vuln/detail/CVE-2018-1312) (CVSS 9.8): In Apache httpd 2.2.0 to 2.4.29, when generating an HTTP Digest authentication challenge, the nonce sent to prevent reply attacks was not correctly generated us
  - [CVE-2021-26691](https://nvd.nist.gov/vuln/detail/CVE-2021-26691) (CVSS 9.8): In Apache HTTP Server versions 2.4.0 to 2.4.46 a specially crafted SessionHeader sent by an origin server could cause a heap overflow
  - [CVE-2021-39275](https://nvd.nist.gov/vuln/detail/CVE-2021-39275) (CVSS 9.8): ap_escape_quotes() may write beyond the end of a buffer when given malicious input. No included modules pass untrusted data to these functions, but third-party 

### 🟡 9929/tcp: Desconocido (MEDIO)

- **Qué es:** Servicio no identificado en la base de conocimiento.
- **Banner:** `(respuesta binaria)`
- **Riesgos:** Todo servicio que no sabes que está corriendo es un riesgo: puede ser software olvidado, sin parches, o incluso malware escuchando conexiones.
- **Recomendación:** Identificar el proceso (Windows: netstat -ano | findstr :PUERTO; Linux: ss -tlnp) y cerrarlo si no es necesario.

## Notas

- Un puerto abierto no es una vulnerabilidad por sí solo: el riesgo depende de si debe estar expuesto y de cómo está configurado.
- Los CVEs se deducen de la versión del banner. Distribuciones como Ubuntu aplican parches sin cambiar el número de versión, así que pueden ser falsos positivos: confírmalos antes de reportarlos.
- Regla general: cierra todo lo que no necesites y limita por firewall lo que sí.
