import { Routes, Route, Link, useNavigate } from 'react-router-dom'
import Shop from './pages/Shop'
import Adoptions from './pages/Adoptions'
import Appointments from './pages/Appointments'
import Admin from './pages/Admin'
import Home from './pages/Home'
import Login from './pages/Login'
import OAuthCallback from './pages/OAuthCallback'
import ProtectedRoute from './components/ProtectedRoute'
import { AuthProvider, useAuth } from './context/AuthContext'
import './App.css'

function NavBar() {
  const { user, role, logout } = useAuth()
  const navigate = useNavigate()

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  return (
    <nav style={{ padding: '1rem', background: '#1a1a2e', display: 'flex', gap: '1rem', alignItems: 'center' }}>
      <Link to="/" style={{ color: 'white' }}>🏠 Inicio</Link>
      <Link to="/shop" style={{ color: 'white' }}>🛒 Tienda</Link>
      <Link to="/adoptions" style={{ color: 'white' }}>🐾 Adopciones</Link>
      {user && <Link to="/appointments" style={{ color: 'white' }}>📅 Citas</Link>}
      {role === 'admin' && <Link to="/admin" style={{ color: 'white' }}>⚙️ Admin</Link>}
      <div style={{ marginLeft: 'auto' }}>
        {user
          ? <button onClick={handleLogout} style={{ color: 'white', background: 'transparent', border: '1px solid white', padding: '0.3rem 0.8rem', borderRadius: '6px', cursor: 'pointer' }}>Cerrar sesión</button>
          : <Link to="/login" style={{ color: 'white' }}>🔐 Login</Link>
        }
      </div>
    </nav>
  )
}

function AppRoutes() {
  return (
    <>
      <NavBar />
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/login" element={<Login />} />
        <Route path="/oauth-callback" element={<OAuthCallback />} />
        <Route path="/shop" element={<Shop />} />
        <Route path="/adoptions" element={<Adoptions />} />
        <Route path="/appointments" element={
          <ProtectedRoute roles={['admin', 'veterinario', 'cliente']}>
            <Appointments />
          </ProtectedRoute>
        } />
        <Route path="/admin" element={
          <ProtectedRoute roles={['admin']}>
            <Admin />
          </ProtectedRoute>
        } />
      </Routes>
    </>
  )
}

function App() {
  return (
    <AuthProvider>
      <AppRoutes />
    </AuthProvider>
  )
}

export default App