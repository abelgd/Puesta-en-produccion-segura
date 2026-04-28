import { createContext, useContext, useState, useEffect } from 'react'

const AuthContext = createContext()

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [token, setToken] = useState(null)
  const [role, setRole] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const savedToken = sessionStorage.getItem('token')
    const savedUser = sessionStorage.getItem('user')
    const savedRole = sessionStorage.getItem('role')
    if (savedToken) {
      setToken(savedToken)
      setUser(JSON.parse(savedUser))
      setRole(savedRole)
    }
    setLoading(false)
  }, [])

  const login = (userData, userToken, userRole) => {
    setUser(userData)
    setToken(userToken)
    setRole(userRole)
    sessionStorage.setItem('token', userToken)
    sessionStorage.setItem('user', JSON.stringify(userData))
    sessionStorage.setItem('role', userRole)
  }

  const logout = () => {
    setUser(null)
    setToken(null)
    setRole(null)
    sessionStorage.clear()
  }

  return (
    <AuthContext.Provider value={{ user, token, role, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => useContext(AuthContext)