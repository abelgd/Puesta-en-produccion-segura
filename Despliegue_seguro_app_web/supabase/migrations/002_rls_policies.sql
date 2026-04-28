-- Habilitar RLS en todas las tablas
alter table profiles enable row level security;
alter table products enable row level security;
alter table pets enable row level security;
alter table adoptions enable row level security;
alter table appointments enable row level security;
alter table orders enable row level security;

-- Profiles: cada usuario ve solo el suyo; admin ve todos
create policy "Users see own profile" on profiles
  for select using (auth.uid() = id);

create policy "Admin sees all profiles" on profiles
  for select using (
    exists (select 1 from profiles where id = auth.uid() and role = 'admin')
  );

-- Products: todos pueden leer; solo admin y ventas pueden escribir
create policy "Anyone reads products" on products
  for select using (true);

create policy "Admin/Ventas manage products" on products
  for all using (
    exists (select 1 from profiles where id = auth.uid() and role in ('admin','ventas'))
  );

-- Pets: todos leen; admin gestiona
create policy "Anyone reads pets" on pets
  for select using (true);

create policy "Admin manages pets" on pets
  for all using (
    exists (select 1 from profiles where id = auth.uid() and role = 'admin')
  );

-- Adoptions: usuario ve las suyas; admin ve todas
create policy "User sees own adoptions" on adoptions
  for select using (auth.uid() = user_id);

create policy "Admin sees all adoptions" on adoptions
  for select using (
    exists (select 1 from profiles where id = auth.uid() and role = 'admin')
  );

-- Appointments: cliente ve las suyas; veterinario ve las asignadas; admin ve todo
create policy "Client sees own appointments" on appointments
  for select using (auth.uid() = user_id);

create policy "Vet sees assigned appointments" on appointments
  for select using (auth.uid() = vet_id);

create policy "Admin manages appointments" on appointments
  for all using (
    exists (select 1 from profiles where id = auth.uid() and role = 'admin')
  );