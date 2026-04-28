import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { supabase } from '../services/supabase'

export default function OAuthCallback() {
  const { login } = useAuth()
  const navigate = useNavigate()

  useEffect(() => {
    supabase.auth.getSession().then(async ({ data: { session } }) => {
      if (!session) { navigate('/login'); return }

      const token = session.access_token
      const user = session.user

      const { data: profile } = await supabase
        .from('profiles')
        .select('role')
        .eq('id', user.id)
        .single()

      if (!profile) {
        await supabase.from('profiles').insert({
          id: user.id,
          email: user.email,
          full_name: user.user_metadata?.full_name || user.user_metadata?.user_name || '',
          role: 'cliente'
        })
      }

      const role = profile?.role || 'cliente'
      login({ id: user.id, email: user.email }, token, role)

      if (role === 'admin') navigate('/admin')
      else if (role === 'veterinario') navigate('/appointments')
      else navigate('/')
    })
  }, [])

  return <p style={{ padding: '2rem' }}>Iniciando sesión con GitHub...</p>
}