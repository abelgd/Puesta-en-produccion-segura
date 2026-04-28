import { useEffect, useState } from 'react'

export default function Adoptions() {
  const [pets, setPets] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    fetch('http://localhost:3000/api/adoptions/pets')
      .then(res => res.json())
      .then(data => {
        setPets(Array.isArray(data) ? data : [])
        setLoading(false)
      })
      .catch(err => {
        setError(err.message)
        setLoading(false)
      })
  }, [])

  if (loading) return <p style={{padding:'2rem'}}>Cargando mascotas...</p>
  if (error) return <p style={{padding:'2rem', color:'red'}}>Error: {error}</p>

  return (
    <div style={{ padding: '2rem' }}>
      <h1>🐾 Mascotas en Adopción</h1>
      {pets.length === 0 ? (
        <p>No hay mascotas disponibles aún.</p>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem', marginTop: '1rem' }}>
          {pets.map(p => (
            <div key={p.id} style={{ border: '1px solid #ccc', padding: '1rem', borderRadius: '8px' }}>
              <h3>{p.name}</h3>
              <p>{p.species} · {p.age} años</p>
              <p>{p.description}</p>
              <span style={{ color: 'green' }}>✅ Disponible</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}