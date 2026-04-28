-- Vista: productos con precio según si el usuario es adoptante
create or replace view products_with_discount as
select
  p.*,
  case
    when pr.is_adoptant = true then p.discounted_price
    else p.price
  end as final_price
from products p
cross join lateral (
  select is_adoptant from profiles where id = auth.uid()
) pr;