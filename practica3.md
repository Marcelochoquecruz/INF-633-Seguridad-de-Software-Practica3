# UNIVERSIDAD AUTÓNOMA TOMÁS FRÍAS  
## FACULTAD DE CIENCIAS PURAS  
### INGENIERÍA INFORMÁTICA  

---

![Logo de la Universidad](./logo.jpg)

---

**Materia:** SEGURIDAD DE SOFTWARE  
**Sigla:** INF-633  

---

**Docente:** **M.Sc. Huascar Fedor Gonzales Guzman**  
**Práctica N°:** **3**  

---

**Auxiliar:**  

**Estudiante:** **Univ. Marcelo Choque Cruz**  

---

**Fecha de presentación:** **15/11/2024**  

---

# Implementación de Prácticas de Seguridad en el Desarrollo de Aplicaciones Web  

## 1. Validación y Sanitización de Entradas  

La validación y sanitización de entradas es un paso fundamental para prevenir ataques de seguridad como la inyección de código y el Cross-Site Scripting (XSS).  

## 1. Pasos Necesarios para Validar y Sanitizar Entradas:  

### R. Proceso de Validación:  

1. **Validación del lado del cliente (Primera capa)**  
   - Implementar validaciones en HTML5 usando atributos como `required`.  
   - Utilizar JavaScript para validaciones complejas.  
   - Mostrar feedback inmediato al usuario.  

2. **Validación del lado del servidor (Capa principal)**  
   - Validar todos los datos recibidos.  
   - Verificar el tipo de datos ingresados.  
   - Comprobar la longitud de las entradas.  
3. **La implementación de validación y sanitización debe:**
    - **Ser Integral:** Múltiples capas de seguridad
    - **Ser Consistente:** Aplicar en toda la aplicación
    - **Ser Mantenible:** Usar código modular y documentado
    - **Ser Actualizable:** Permitir mejoras de seguridad
### Ejemplo de Validación de Email y Sanitización (PHP):  

```php
<?php
class SecurityValidator {
    public function validateEmail($email) {
        $email = trim($email);
        
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return false;
        }
        
        $pattern = '/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/';
        if (!preg_match($pattern, $email)) {
            return false;
        }
        
        return true;
    }
    
    public function sanitizeText($input) {
        $text = trim($input);
        $text = htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
        return $text;
    }
}
?>
```
## 2. Control de Acceso y Autenticación Segura

## Beneficios de la Autenticación Multifactor (MFA)

### 2.1 Capas de Seguridad Adicionales
- **Algo que sabes:** Contraseña  
- **Algo que tienes:** Dispositivo móvil, token físico  
- **Algo que eres:** Datos biométricos  

### 2.2 Ventajas Principales

 **Mayor Seguridad:**
   - Protección contra robo de credenciales  
   - Minimiza riesgos de phishing  
   - Reduce accesos no autorizados  

 **Flexibilidad:**
   - Múltiples opciones de verificación  
   - Adaptable a diferentes niveles de seguridad  
   - Personalizable según necesidades  

**Cumplimiento Normativo:**
   - Ayuda a cumplir regulaciones  
   - Mejora la auditoría de accesos  
   - Facilita la gestión de identidades  

---

## 2.3 Autenticación Basada en Tokens (JWT)

### Beneficios de JWT

  **Stateless:**
   - No requiere almacenamiento en servidor  
   - Reduce carga en base de datos  
   - Mejora escalabilidad  

  **Seguridad:**
   - Firmado digitalmente  
   - Información encriptada  
   - Tiempo de expiración configurable  

  **Versatilidad:**
   - Cross-domain  
   - Múltiples lenguajes soportados  
   - Fácil integración con APIs  

---

## Implementación Práctica de JWT

### Ejemplo en Node.js
```javascript
const jwt = require('jsonwebtoken');
const express = require('express');
const app = express();

// Clave secreta para firmar el token
const SECRET_KEY = 'tu_clave_secreta_muy_segura';

// Middleware para procesar JSON
app.use(express.json());

// Función para crear usuario y generar token
const createUserToken = (userData) => {
   // Payload del token
   const payload = {
       id: userData.id,
       username: userData.username,
       role: userData.role,
       iat: Date.now(),
       exp: Date.now() + (60 * 60 * 1000) // 1 hora de expiración
   };

   // Generar token
   return jwt.sign(payload, SECRET_KEY);
};

// Ruta de login
app.post('/login', (req, res) => {
   // Simulación de verificación de credenciales
   const user = {
       id: 1,
       username: req.body.username,
       role: 'user'
   };

   try {
       // Generar token
       const token = createUserToken(user);

       // Respuesta exitosa
       res.json({
           success: true,
           token: token,
           message: 'Login exitoso'
       });
   } catch (error) {
       res.status(500).json({
           success: false,
           message: 'Error al generar token'
       });
   }
});

// Middleware de verificación de token
const verifyToken = (req, res, next) => {
   const token = req.headers['authorization'];

   if (!token) {
       return res.status(401).json({
           success: false,
           message: 'Token no proporcionado'
       });
   }

   try {
       // Verificar token
       const decoded = jwt.verify(token, SECRET_KEY);
       req.user = decoded;
       next();
   } catch (error) {
       res.status(401).json({
           success: false,
           message: 'Token inválido'
       });
   }
};

// Ruta protegida
app.get('/protected', verifyToken, (req, res) => {
   res.json({
       success: true,
       data: 'Datos protegidos',
       user: req.user
   });
});

// Iniciar servidor
app.listen(3000, () => {
   console.log('Servidor ejecutándose en http://localhost:3000');
});
```
# 3. Gestión de Sesiones y Cookies

## 3.1. Atributos de Seguridad en Cookies

### 3.1.1. Atributo HttpOnly
- **Definición:** Evita el acceso a las cookies mediante JavaScript
- **Propósito:** Previene ataques XSS que intentan robar cookies de sesión
- **Beneficios:**
 - Protección contra robo de sesión
 - Mayor seguridad en datos sensibles
 - Aislamiento de la capa de cliente

### 3.1.2. Atributo Secure
- **Definición:** Asegura que las cookies solo se envíen por HTTPS
- **Propósito:** Previene interceptación de datos en tránsito
- **Beneficios:**
 - Encriptación en la transmisión
 - Protección contra ataques Man-in-the-Middle
 - Garantía de integridad de datos

## 3.2. Implementación Práctica

### Ejemplo en PHP
```php
<?php
// Configuración segura de sesión
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.use_only_cookies', 1);

// Iniciar sesión con configuración segura
session_start([
   'cookie_httponly' => true,
   'cookie_secure' => true,
   'use_strict_mode' => true,
   'cookie_samesite' => 'Lax'
]);

// Función para crear cookie segura
function setSecureCookie($name, $value, $expiry) {
   setcookie($name, $value, [
       'expires' => time() + $expiry,
       'path' => '/',
       'domain' => $_SERVER['HTTP_HOST'],
       'secure' => true,
       'httponly' => true,
       'samesite' => 'Lax'
   ]);
}

// Ejemplo de uso
setSecureCookie('user_preference', 'dark_mode', 3600);
```
## 3.1.Consideraciones y Conclusión

## Consideraciones Generales
3.1. **Gestión de Sesión y Cookies:**  
   - Regenerar el ID de sesión y configurar tiempos de expiración son fundamentales para evitar ataques como **Session Fixation**.  
   - Usar cookies con atributos de seguridad como **SameSite**, **HttpOnly**, y **Secure** minimiza riesgos asociados a ataques **CSRF** y manipulaciones maliciosas.

3.2. **Prevención de Ataques:**  
   - La implementación de **tokens CSRF** y la validación del origen de las peticiones fortalecen la protección contra ataques **Cross-Site Request Forgery**.  
   - Monitorear patrones de comportamiento y registrar eventos sospechosos ayudan a detectar y prevenir accesos no autorizados.

3.3. **Monitoreo y Registro:**  
   - Registrar eventos como intentos de inicio de sesión, cambios en las sesiones y accesos sospechosos permite un análisis proactivo de seguridad.  
   - Configurar alertas de seguridad para detectar múltiples fallos de autenticación o accesos desde ubicaciones inusuales mejora la respuesta a incidentes.

---

## Conclusión
La implementación de prácticas de seguridad robustas es esencial para garantizar la integridad y confidencialidad de las sesiones y datos de usuario. Las claves para una gestión segura son:  
- **Implementación Rigurosa:** Aplicar controles como regeneración de ID, tokens CSRF, y configuración estricta de cookies.  
- **Monitoreo Constante:** Detectar patrones anómalos y responder a actividades sospechosas en tiempo real.  
- **Actualización y Pruebas:** Revisar y actualizar regularmente las configuraciones de seguridad, y realizar pruebas periódicas para identificar vulnerabilidades.  

Al adoptar estas estrategias, se fortalecen las barreras contra amenazas y se promueve la confianza del usuario en los sistemas.  
# 4. Protección de Datos Sensibles

## 4.1 Diferencias entre Hashing y Cifrado

### 4.1.1 Hashing
- **Definición:** Función unidireccional que genera una huella digital única.
- **Características:**
  - No reversible.
  - Mismo input genera mismo output.
  - Un cambio mínimo en el input genera un hash completamente diferente.
  
- **Casos de Uso:**
  1. Almacenamiento de contraseñas.
  2. Verificación de integridad de archivos.
  3. Firmas digitales.
  4. Detección de duplicados.

### 4.1.2 Cifrado
- **Definición:** Proceso reversible que convierte datos en un formato ilegible.
- **Características:**
  - Reversible con clave.
  - Mantiene longitud de datos similar.
  - Puede ser simétrico o asimétrico.

- **Casos de Uso:**
  1. Comunicación segura.
  2. Almacenamiento de datos personales.
  3. Transferencia de información confidencial.
  4. Protección de archivos sensibles.

## 4.2 Implementación en PHP

### 4.2.1 Gestión Segura de Contraseñas

```php
<?php
class PasswordManager {
   // Opciones de hash
   private $options = [
       'cost' => 12,  // Costo computacional
       'memory_cost' => 1024,  // Uso de memoria
       'time_cost' => 2   // Tiempo de procesamiento
   ];

   /**
    * Genera hash seguro de contraseña
    * @param string $password
    * @return string
    */
   public function hashPassword($password) {
       try {
           $hashedPassword = password_hash(
               $password,
               PASSWORD_ARGON2ID,  // Algoritmo más seguro
               $this->options
           );

           if ($hashedPassword === false) {
               throw new Exception('Error al generar hash');
           }

           return $hashedPassword;

       } catch (Exception $e) {
           error_log("Error en hashPassword: " . $e->getMessage());
           throw $e;
       }
   }

   /**
    * Verifica contraseña contra hash
    * @param string $password
    * @param string $hash
    * @return bool
    */
   public function verifyPassword($password, $hash) {
       try {
           return password_verify($password, $hash);
       } catch (Exception $e) {
           error_log("Error en verifyPassword: " . $e->getMessage());
           throw $e;
       }
   }

   /**
    * Verifica si el hash necesita actualización
    * @param string $hash
    * @return bool
    */
   public function needsRehash($hash) {
       return password_needs_rehash(
           $hash,
           PASSWORD_ARGON2ID,
           $this->options
       );
   }
}

// Ejemplo de uso
class UserAuth {
   private $passwordManager;
   private $db;  // Instancia de conexión a base de datos

   public function __construct() {
       $this->passwordManager = new PasswordManager();
       // Inicializar conexión a base de datos
   }

   /**
    * Registra nuevo usuario
    * @param string $username
    * @param string $password
    * @return bool
    */
   public function register($username, $password) {
       try {
           // Generar hash de contraseña
           $hashedPassword = $this->passwordManager->hashPassword($password);

           // Guardar en base de datos (ejemplo)
           $query = "INSERT INTO users (username, password_hash) VALUES (?, ?)";
           // Ejecutar query con $username y $hashedPassword
           
           return true;
       } catch (Exception $e) {
           error_log("Error en registro: " . $e->getMessage());
           return false;
       }
   }

   /**
    * Valida credenciales de usuario
    * @param string $username
    * @param string $password
    * @return bool
    */
   public function login($username, $password) {
       try {
           // Obtener hash de base de datos (ejemplo)
           $storedHash = ""; // Obtener de base de datos

           if ($this->passwordManager->verifyPassword($password, $storedHash)) {
               // Verificar si necesita actualización
               if ($this->passwordManager->needsRehash($storedHash)) {
                   $newHash = $this->passwordManager->hashPassword($password);
                   // Actualizar hash en base de datos
               }
               return true;
           }
           return false;
       } catch (Exception $e) {
           error_log("Error en login: " . $e->getMessage());
           return false;
       }
   }
}
?>
```
### 4.2.2 Ejemplo de Uso

### Ejemplo de Registro y Login de Usuario en PHP

```php
// Crear instancia
$auth = new UserAuth();

// Registro de usuario
try {
    if ($auth->register("usuario1", "contraseña123")) {
        echo "Usuario registrado exitosamente";
    }
} catch (Exception $e) {
    echo "Error en registro: " . $e->getMessage();
}

// Inicio de sesión
try {
    if ($auth->login("usuario1", "contraseña123")) {
        echo "Login exitoso";
    } else {
        echo "Credenciales inválidas";
    }
} catch (Exception $e) {
    echo "Error en login: " . $e->getMessage();
}
```
# 4.2 Mejores Prácticas de Seguridad

## 4.2.1 Para Hashing

### Algoritmos Recomendados:
- **Argon2id**: Es la opción más segura y recomendada.
- **bcrypt**: Una alternativa sólida y ampliamente utilizada.
- **PBKDF2**: Solo si no están disponibles los anteriores.

### Configuración:
- **Usar costos adecuados**: Asegúrate de usar un costo que balancee seguridad y rendimiento.
- **Implementar salt único**: Cada contraseña debe tener un salt único para evitar ataques de diccionario.
- **Actualizar hashes antiguos**: Rehash cuando sea necesario para mantener la seguridad con algoritmos más recientes.

## 4.2.2 Para Cifrado

### Algoritmos Seguros:
- **AES-256-GCM**: Muy seguro y eficiente para cifrado simétrico.
- **ChaCha20-Poly1305**: Una buena alternativa si no se puede usar AES.
- **RSA**: Ideal para cifrado asimétrico y autenticación.

### Gestión de Claves:
- **Rotación periódica**: Cambia las claves regularmente para minimizar riesgos de exposición.
- **Almacenamiento seguro**: Guarda las claves de forma segura, como en módulos de seguridad (HSM).
- **Respaldo protegido**: Asegúrate de que las claves de respaldo estén cifradas y almacenadas en un lugar seguro.

# 4.3 Conclusiones

La protección de datos sensibles es clave en la seguridad informática, y se debe tomar en cuenta lo siguiente:

- **Elección correcta de técnicas**: Usar hashing para contraseñas y cifrado para datos sensibles, dependiendo del caso.
- **Implementación segura**: Asegúrate de usar los algoritmos más seguros y configuraciones adecuadas.
- **Mantenimiento constante**: La seguridad no es algo estático. Mantén las configuraciones actualizadas y realiza auditorías periódicas.
- **Documentación clara**: Es importante documentar todos los procedimientos de seguridad para mantener la consistencia y cumplir con normativas.
