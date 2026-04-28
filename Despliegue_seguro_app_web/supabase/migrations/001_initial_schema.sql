-- Roles de usuario
create type user_role as enum ('admin', 'cliente', 'veterinario', 'ventas');

-- Tabla de perfiles (vinculada a auth.users)
create table profiles (
  id uuid references auth.users on delete cascade primary key,
  email text,
  full_name text,
  role user_role default 'cliente',
  is_adoptant boolean default false,
  created_at timestamptz default now()
);

-- Productos de la tienda
create table products (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  description text,
  price numeric not null,
  discounted_price numeric,
  stock int default 0,
  category text,
  created_at timestamptz default now()
);

-- Mascotas en adopción
create table pets (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  species text,
  age int,
  description text,
  status text default 'disponible', -- disponible, adoptado
  created_at timestamptz default now()
);

-- Adopciones
create table adoptions (
  id uuid primary key default gen_random_uuid(),
  pet_id uuid references pets(id),
  user_id uuid references profiles(id),
  adopted_at timestamptz default now()
);

-- Citas veterinarias
create table appointments (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references profiles(id),
  vet_id uuid references profiles(id),
  pet_name text,
  date timestamptz,
  status text default 'pendiente',
  notes text,
  created_at timestamptz default now()
);

-- Pedidos de la tienda
create table orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references profiles(id),
  product_id uuid references products(id),
  quantity int default 1,
  total_price numeric,
  created_at timestamptz default now()
);