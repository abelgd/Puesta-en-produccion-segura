import { useEffect, useState } from 'react'
import { useAuth } from '../context/AuthContext'

export default function Admin() {
  const { token } = useAuth()
  const [stats, setStats] = useState({ pets: 0, appointments: 0, products: 0 })
  const [appointments, setAppointments] = useState([])
  const [pets, setPets] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const headers = { Authorization: `Bearer ${token}` }

    Promise.all([
      fetch('http://localhost:3000/api/appointments', { headers }).then(r => r.json()),
      fetch('http://localhost:3000/api/adoptions/pets').then(r => r.json()),
      fetch('http://localhost:3000/api/shop').then(r => r.json())
    ]).then(([appts, petsData, products]) => {
      setAppointments(Array.isArray(appts) ? appts : [])
      setPets(Array.isArray(petsData) ? petsData : [])
      setStats({
        appointments: Array.isArray(appts) ? appts.length : 0,
        pets: Array.isArray(petsData) ? petsData.length : 0,
        products: Array.isArray(products) ? products.length : 0
      })
      setLoading(false)
    }).catch(() => setLoading(false))
  }, [token])

  if (loading) return <p style={{ padding: '2rem' }}>Cargando panel...</p>

  return (
    <div style={{ padding: '2rem', maxWidth: '1000px', margin: '0 auto' }}>
      <h1 style={{ marginBottom: '2rem' }}>⚙️ Panel de Administración</h1>

      {/* Estadísticas */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem', marginBottom: '2rem' }}>
        {[
          { label: '📅 Citas', value: stats.appointments },
          { label: '🐾 Mascotas', value: stats.pets },
          { label: '🛒 Productos', value: stats.products }
        ].map(s => (
          <div key={s.label} style={{ background: '#1a1a2e', color: 'white', padding: '1.5rem', borderRadius: '12px', textAlign: 'center' }}>
            <p style={{ fontSize: '2rem', fontWeight: 'bold' }}>{s.value}</p>
            <p>{s.label}</p>
          </div>
        ))}
      </div>

      {/* Citas recientes */}
      <h2 style={{ marginBottom: '1rem' }}>📅 Citas recientes</h2>
      <table style={{ width: '100%', borderCollapse: 'collapse', marginBottom: '2rem' }}>
        <thead>
          <tr style={{ background: '#f0f0f0' }}>
            <th style={{ padding: '0.75rem', textAlign: 'left' }}>Mascota</th>
            <th style={{ padding: '0.75rem', textAlign: 'left' }}>Fecha</th>
            <th style={{ padding: '0.75rem', textAlign: 'left' }}>Estado</th>
          </tr>
        </thead>
        <tbody>
          {appointments.slice(0, 5).map(a => (
            <tr key={a.id} style={{ borderBottom: '1px solid #eee' }}>
              <td style={{ padding: '0.75rem' }}>{a.pet_name}</td>
              <td style={{ padding: '0.75rem' }}>{new Date(a.date).toLocaleDateString('es-ES')}</td>
              <td style={{ padding: '0.75rem' }}>{a.status}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {/* Mascotas */}
      <h2 style={{ marginBottom: '1rem' }}>🐾 Mascotas disponibles</h2>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '1rem' }}>
        {pets.map(p => (
          <div key={p.id} style={{ border: '1px solid #ddd', borderRadius: '10px', padding: '1rem' }}>
            <h3>{p.name}</h3>
            <p style={{ color: '#666', fontSize: '0.9rem' }}>{p.species} · {p.age} años</p>
            <p style={{ color: p.status === 'disponible' ? 'green' : 'red', fontSize: '0.85rem', fontWeight: 'bold' }}>{p.status}</p>
          </div>
        ))}
      </div>
    </div>
  )
}