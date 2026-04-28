import { useEffect, useState } from 'react'

export default function Shop() {
  const [products, setProducts] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch('http://localhost:3000/api/shop')
      .then(res => res.json())
      .then(data => {
        setProducts(data)
        setLoading(false)
      })
  }, [])

  if (loading) return <p>Cargando productos...</p>

  return (
    <div style={{ padding: '2rem' }}>
      <h1>🛒 Tienda Veterinaria</h1>
      {products.length === 0 ? (
        <p>No hay productos aún.</p>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem' }}>
          {products.map(p => (
            <div key={p.id} style={{ border: '1px solid #ccc', padding: '1rem', borderRadius: '8px' }}>
              <h3>{p.name}</h3>
              <p>{p.description}</p>
              <strong>{p.price}€</strong>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
