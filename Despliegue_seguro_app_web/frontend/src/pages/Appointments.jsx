import { useEffect, useState } from 'react'
import { useAuth } from '../context/AuthContext'

export default function Appointments() {
  const { token, role, user } = useAuth()
  const [appointments, setAppointments] = useState([])
  const [loading, setLoading] = useState(true)

  const [form, setForm] = useState({ pet_name: '', date: '', notes: '' })
  const [submitting, setSubmitting] = useState(false)
  const [success, setSuccess] = useState('')
  const [error, setError] = useState('')

  const fetchAppointments = () => {
    setLoading(true)
    fetch('http://localhost:3000/api/appointments', {
      headers: { Authorization: `Bearer ${token}` }
    })
      .then(res => res.json())
      .then(data => { setAppointments(Array.isArray(data) ? data : []); setLoading(false) })
      .catch(() => setLoading(false))
  }

  useEffect(() => {
    if (token) fetchAppointments()
  }, [token])

  const updateStatus = async (id, status) => {
    await fetch(`http://localhost:3000/api/appointments/${id}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify({ status })
    })
    setAppointments(prev => prev.map(a => a.id === id ? { ...a, status } : a))
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setSubmitting(true)
    setError('')
    setSuccess('')

    const res = await fetch('http://localhost:3000/api/appointments', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify(form)
    })

    if (res.ok) {
      setSuccess('¡Cita solicitada correctamente!')
      setForm({ pet_name: '', date: '', notes: '' })
      fetchAppointments()
    } else {
      const data = await res.json()
      setError(data.error || 'Error al crear la cita')
    }
    setSubmitting(false)
  }

  const today = new Date().toISOString().split('T')[0]

  if (loading) return <p style={{ padding: '2rem' }}>Cargando citas...</p>

  return (
    <div style={{ padding: '2rem', maxWidth: '900px', margin: '0 auto' }}>
      <h1 style={{ marginBottom: '1.5rem' }}>📅 Citas Veterinarias</h1>

      {/* FORMULARIO solo para clientes */}
      {role === 'cliente' && (
        <div style={{ background: '#f9f9f9', border: '1px solid #ddd', borderRadius: '10px', padding: '1.5rem', marginBottom: '2rem' }}>
          <h2 style={{ marginBottom: '1rem', fontSize: '1.1rem' }}>Pedir nueva cita</h2>
          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
              <div style={{ flex: 1, minWidth: '180px' }}>
                <label style={{ display: 'block', marginBottom: '0.25rem', fontSize: '0.9rem' }}>Nombre de la mascota</label>
                <input
                  type="text"
                  required
                  placeholder="Ej: Max"
                  value={form.pet_name}
                  onChange={e => setForm({ ...form, pet_name: e.target.value })}
                  style={{ width: '100%', padding: '0.5rem 0.75rem', borderRadius: '6px', border: '1px solid #ccc', fontSize: '0.9rem' }}
                />
              </div>
              <div style={{ flex: 1, minWidth: '180px' }}>
                <label style={{ display: 'block', marginBottom: '0.25rem', fontSize: '0.9rem' }}>Fecha</label>
                <input
                  type="date"
                  required
                  min={today}
                  value={form.date}
                  onChange={e => setForm({ ...form, date: e.target.value })}
                  style={{ width: '100%', padding: '0.5rem 0.75rem', borderRadius: '6px', border: '1px solid #ccc', fontSize: '0.9rem' }}
                />
              </div>
            </div>
            <div>
              <label style={{ display: 'block', marginBottom: '0.25rem', fontSize: '0.9rem' }}>Notas (opcional)</label>
              <textarea
                rows={2}
                placeholder="Motivo de la consulta..."
                value={form.notes}
                onChange={e => setForm({ ...form, notes: e.target.value })}
                style={{ width: '100%', padding: '0.5rem 0.75rem', borderRadius: '6px', border: '1px solid #ccc', fontSize: '0.9rem', resize: 'none' }}
              />
            </div>

            {error && <p style={{ color: 'red', fontSize: '0.85rem' }}>{error}</p>}
            {success && <p style={{ color: 'green', fontSize: '0.85rem' }}>{success}</p>}

            <button
              type="submit"
              disabled={submitting}
              style={{ alignSelf: 'flex-start', padding: '0.5rem 1.25rem', background: '#1a1a2e', color: 'white', border: 'none', borderRadius: '6px', cursor: 'pointer', opacity: submitting ? 0.6 : 1 }}
            >
              {submitting ? 'Enviando...' : 'Solicitar cita'}
            </button>
          </form>
        </div>
      )}

      {/* TABLA DE CITAS */}
      {appointments.length === 0 ? (
        <p>{role === 'cliente' ? 'Aún no tienes citas.' : 'No hay citas registradas.'}</p>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ background: '#1a1a2e', color: 'white' }}>
              <th style={{ padding: '0.75rem', textAlign: 'left' }}>Mascota</th>
              <th style={{ padding: '0.75rem', textAlign: 'left' }}>Fecha</th>
              <th style={{ padding: '0.75rem', textAlign: 'left' }}>Notas</th>
              <th style={{ padding: '0.75rem', textAlign: 'left' }}>Estado</th>
              {(role === 'veterinario' || role === 'admin') && (
                <th style={{ padding: '0.75rem', textAlign: 'left' }}>Acción</th>
              )}
            </tr>
          </thead>
          <tbody>
            {appointments.map(a => (
              <tr key={a.id} style={{ borderBottom: '1px solid #eee' }}>
                <td style={{ padding: '0.75rem' }}>{a.pet_name}</td>
                <td style={{ padding: '0.75rem' }}>{new Date(a.date).toLocaleDateString('es-ES')}</td>
                <td style={{ padding: '0.75rem' }}>{a.notes || '—'}</td>
                <td style={{ padding: '0.75rem' }}>
                  <span style={{
                    padding: '0.25rem 0.75rem',
                    borderRadius: '999px',
                    background: a.status === 'completada' ? '#d4edda' : a.status === 'cancelada' ? '#f8d7da' : '#fff3cd',
                    color: a.status === 'completada' ? '#155724' : a.status === 'cancelada' ? '#721c24' : '#856404',
                    fontSize: '0.85rem'
                  }}>
                    {a.status}
                  </span>
                </td>
                {(role === 'veterinario' || role === 'admin') && (
                  <td style={{ padding: '0.75rem', display: 'flex', gap: '0.5rem' }}>
                    <button onClick={() => updateStatus(a.id, 'completada')} style={{ padding: '0.3rem 0.6rem', background: '#28a745', color: 'white', border: 'none', borderRadius: '6px', cursor: 'pointer' }}>✅</button>
                    <button onClick={() => updateStatus(a.id, 'cancelada')} style={{ padding: '0.3rem 0.6rem', background: '#dc3545', color: 'white', border: 'none', borderRadius: '6px', cursor: 'pointer' }}>❌</button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}