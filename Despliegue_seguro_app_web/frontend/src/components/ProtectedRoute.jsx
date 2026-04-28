import { Navigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

export default function ProtectedRoute({ children, roles }) {
  const { user, role, loading } = useAuth()

  if (loading) return <p>Cargando...</p>
  if (!user) return <Navigate to="/login" />
  if (roles && !roles.includes(role)) return <Navigate to="/" />

  return children
}