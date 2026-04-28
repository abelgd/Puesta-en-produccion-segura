# Despliegue seguro de aplicación web

# VetClinic App

Aplicación web fullstack para la gestión de una clínica veterinaria. Permite a clientes pedir citas, explorar productos y ver mascotas en adopción, mientras que veterinarios y administradores gestionan el sistema con distintos niveles de acceso.

***

## Tecnologías utilizadas

### Frontend
- **React** + **Vite**
- **React Router v6** — navegación y rutas protegidas
- **Tailwind CSS** — estilos
- **Context API** — gestión de estado global de autenticación

### Backend
- **Node.js** + **Express**
- **JWT (JSON Web Tokens)** — autenticación stateless
- **Middleware RBAC** — control de acceso por roles
- **Supabase** — base de datos PostgreSQL como servicio

### Base de datos
- **Supabase (PostgreSQL)**
  - Tablas: `profiles`, `appointments`, `products`, `adoptions`

***

## Estructura del proyecto

```
project/
├── frontend/
│   ├── src/
│   │   ├── context/
│   │   │   └── AuthContext.jsx        # Contexto global de autenticación
│   │   ├── pages/
│   │   │   ├── Login.jsx              # Login con email/contraseña y GitHub OAuth2
│   │   │   ├── AdminPanel.jsx         # Panel de administración con estadísticas
│   │   │   ├── Appointments.jsx       # Citas (crear para clientes, gestionar para vets)
│   │   │   ├── Shop.jsx               # Tienda de productos
│   │   │   └── Adoptions.jsx          # Mascotas en adopción
│   │   ├── components/
│   │   │   └── Navbar.jsx             # Barra de navegación con control por rol
│   │   ├── router/
│   │   │   └── AppRouter.jsx          # Rutas protegidas por rol
│   │   └── main.jsx
│
├── backend/
│   └── src/
│       ├── controllers/
│       │   ├── auth.controller.js         # Login, registro, OAuth callback
│       │   ├── appointments.controller.js # CRUD citas con ABAC
│       │   ├── products.controller.js     # Listado de productos
│       │   └── adoptions.controller.js    # Listado de adopciones
│       ├── routes/
│       │   ├── auth.routes.js
│       │   ├── appointments.routes.js
│       │   ├── products.routes.js
│       │   └── adoptions.routes.js
│       ├── middleware/
│       │   ├── auth.js                # Verificación JWT
│       │   └── rbac.js                # Control de acceso por roles
│       ├── services/
│       │   └── supabase.js            # Cliente Supabase
│       └── index.js                   # Servidor Express
```

***

## Sistema de autenticación

### Login con email y contraseña
- El usuario introduce sus credenciales en el frontend
- El backend verifica el usuario en Supabase y devuelve un **JWT firmado**
- El token se almacena en memoria (AuthContext) y se envía en cada petición como `Authorization: Bearer <token>`

### OAuth2 con GitHub
- El usuario hace clic en "Continuar con GitHub"
- Supabase gestiona el flujo OAuth2 con GitHub
- Tras autenticarse, Supabase devuelve la sesión al frontend
- Se crea automáticamente un perfil en la tabla `profiles` si es la primera vez

### Roles disponibles

| Rol | Permisos |
|-----|----------|
| `admin` | Acceso total: panel de administración, gestión de citas, productos y adopciones |
| `veterinario` | Ver y gestionar todas las citas (aceptar/rechazar), ver productos y adopciones |
| `cliente` | Pedir citas, ver sus propias citas, explorar tienda y adopciones |

***

## Control de acceso

### RBAC — Role-Based Access Control
Implementado como middleware en Express. Cada ruta especifica qué roles tienen acceso:

```js
// Solo admin y veterinario pueden cambiar estado de una cita
router.patch('/:id', auth, rbac('admin', 'veterinario'), ctrl.updateStatus);
```

### ABAC — Attribute-Based Access Control
Los clientes solo pueden ver sus propias citas. El controlador comprueba el rol del usuario y filtra los resultados:

```js
if (profile?.role === 'cliente') {
  query = query.eq('user_id', req.user.id);
}
```

### Rutas protegidas en el frontend
El componente `ProtectedRoute` en el router verifica el rol antes de renderizar la página:

```jsx
<ProtectedRoute allowedRoles={['admin']}>
  <AdminPanel />
</ProtectedRoute>
```

***

## Módulo de Citas

### Flujo completo

1. El cliente entra en `/appointments` y rellena el formulario (nombre de mascota, fecha, notas)
2. Se hace un `POST /api/appointments` con el token JWT
3. La cita se guarda en Supabase con `status: 'pendiente'`
4. El veterinario o admin ve todas las citas y puede marcarlas como `completada` o `cancelada`
5. El cliente solo ve sus propias citas

### Endpoints

| Método | Ruta | Roles | Descripción |
|--------|------|-------|-------------|
| GET | `/api/appointments` | Todos | Devuelve citas (filtradas por rol) |
| POST | `/api/appointments` | Todos | Crear nueva cita |
| PATCH | `/api/appointments/:id` | admin, veterinario | Actualizar estado |

***

##  Tienda y Adopciones

- `/shop` — Listado de productos de la clínica (solo lectura)
- `/adoptions` — Mascotas disponibles para adopción (solo lectura)
- Ambas rutas requieren autenticación

***

## Base de datos (Supabase)

### Tabla `profiles`
```sql
id        uuid (FK → auth.users)
email     text
role      text  -- 'admin' | 'veterinario' | 'cliente'
```

### Tabla `appointments`
```sql
id        uuid
user_id   uuid (FK → profiles)
pet_name  text
date      date
notes     text
status    text  -- 'pendiente' | 'completada' | 'cancelada'
```

### Tabla `products`
```sql
id          uuid
name        text
description text
price       numeric
image_url   text
```

### Tabla `adoptions`
```sql
id          uuid
name        text
species     text
age         int
description text
image_url   text
available   boolean
```

***

## Instalación y ejecución local

### Requisitos
- Node.js 18+
- Cuenta en [Supabase](https://supabase.com)
- Cuenta en GitHub (para OAuth2)

### 1. Clonar el repositorio
```bash
git clone https://github.com/tu-usuario/vetclinic-app.git
cd vetclinic-app
```

### 2. Configurar el backend
```bash
cd backend
npm install
```

Crea el archivo `backend/.env`:
```env
PORT=3000
SUPABASE_URL=https://xxxx.supabase.co
SUPABASE_SERVICE_KEY=your_service_role_key
JWT_SECRET=your_jwt_secret
```

### 3. Configurar el frontend
```bash
cd frontend
npm install
```

Crea el archivo `frontend/.env`:
```env
VITE_SUPABASE_URL=https://xxxx.supabase.co
VITE_SUPABASE_ANON_KEY=your_anon_key
```

### 4. Ejecutar en desarrollo
```bash
# Terminal 1 — backend
cd backend && npm run dev

# Terminal 2 — frontend
cd frontend && npm run dev
```

La app estará disponible en `http://localhost:5173`

***

## Variables de entorno

| Variable | Dónde | Descripción |
|----------|-------|-------------|
| `PORT` | backend | Puerto del servidor Express |
| `SUPABASE_URL` | backend + frontend | URL del proyecto Supabase |
| `SUPABASE_SERVICE_KEY` | backend | Clave de servicio (solo backend) |
| `SUPABASE_ANON_KEY` | frontend | Clave pública anon |
| `JWT_SECRET` | backend | Secreto para firmar tokens JWT |

***

## Autor

Desarrollado por **Abel García Domínguez**  
Proyecto de aplicación web segura con autenticación, autorización y gestión de roles.
