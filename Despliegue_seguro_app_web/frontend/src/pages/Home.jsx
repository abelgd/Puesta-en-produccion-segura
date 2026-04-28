import { Link } from 'react-router-dom'

export default function Home() {
  return (
    <div style={{ maxWidth: '800px', margin: '4rem auto', padding: '2rem', textAlign: 'center' }}>

      <h1 style={{ fontSize: '2.5rem', marginBottom: '0.5rem' }}>
        🐾 Clínica Veterinaria
      </h1>
      <p style={{ color: '#666', fontSize: '1.1rem', marginBottom: '3rem' }}>
        Tu centro de confianza para el cuidado, adopción y bienestar de tus mascotas
      </p>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1.5rem' }}>

        <Link to="/shop" style={{ textDecoration: 'none' }}>
          <div style={cardStyle}>
            <span style={{ fontSize: '2.5rem' }}>🛒</span>
            <h3>Tienda</h3>
            <p style={{ color: '#888', fontSize: '0.9rem' }}>
              Productos y alimentos para tu mascota
            </p>
          </div>
        </Link>

        <Link to="/adoptions" style={{ textDecoration: 'none' }}>
          <div style={cardStyle}>
            <span style={{ fontSize: '2.5rem' }}>🐶</span>
            <h3>Adopciones</h3>
            <p style={{ color: '#888', fontSize: '0.9rem' }}>
              Dale un hogar a quien más lo necesita
            </p>
          </div>
        </Link>

        <Link to="/appointments" style={{ textDecoration: 'none' }}>
          <div style={cardStyle}>
            <span style={{ fontSize: '2.5rem' }}>📅</span>
            <h3>Citas</h3>
            <p style={{ color: '#888', fontSize: '0.9rem' }}>
              Reserva tu cita veterinaria
            </p>
          </div>
        </Link>

      </div>

      <p style={{ marginTop: '3rem', color: '#aaa', fontSize: '0.85rem' }}>
        🐾 Los clientes que adopten mascotas reciben <strong>20% de descuento</strong> en la tienda
      </p>

    </div>
  )
}

const cardStyle = {
  border: '1px solid #e0e0e0',
  borderRadius: '12px',
  padding: '2rem 1rem',
  color: '#1a1a2e',
  transition: 'box-shadow 0.2s',
  cursor: 'pointer',
  background: 'white'
}