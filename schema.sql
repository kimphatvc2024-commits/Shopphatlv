create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  balance bigint not null default 0 check (balance >= 0),
  role text not null default 'member' check (role in ('member','admin')),
  created_at timestamptz not null default now()
);

create table if not exists public.products (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  category text not null default 'Sản phẩm',
  description text not null default '',
  price bigint not null check (price >= 0),
  active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.topup_requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  amount bigint not null check (amount >= 1000),
  reference text not null unique,
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  created_at timestamptz not null default now(),
  reviewed_at timestamptz
);

create table if not exists public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  product_id uuid references public.products(id),
  product_name text not null,
  amount bigint not null check (amount >= 0),
  status text not null default 'received',
  created_at timestamptz not null default now()
);

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path=public
as $$
begin
  insert into public.profiles(id,email) values(new.id,new.email)
  on conflict(id) do update set email=excluded.email;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
for each row execute procedure public.handle_new_user();

create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path=public
as $$
  select exists(select 1 from public.profiles where id=auth.uid() and role='admin');
$$;

alter table public.profiles enable row level security;
alter table public.products enable row level security;
alter table public.topup_requests enable row level security;
alter table public.orders enable row level security;

drop policy if exists "profile read own" on public.profiles;
create policy "profile read own" on public.profiles for select to authenticated using(id=auth.uid());
drop policy if exists "products public read active" on public.products;
create policy "products public read active" on public.products for select using(active=true or public.is_admin());
drop policy if exists "admin manage products" on public.products;
create policy "admin manage products" on public.products for all to authenticated using(public.is_admin()) with check(public.is_admin());
drop policy if exists "user create own topup" on public.topup_requests;
create policy "user create own topup" on public.topup_requests for insert to authenticated with check(user_id=auth.uid() and status='pending');
drop policy if exists "user read own topup" on public.topup_requests;
create policy "user read own topup" on public.topup_requests for select to authenticated using(user_id=auth.uid() or public.is_admin());
drop policy if exists "user read own orders" on public.orders;
create policy "user read own orders" on public.orders for select to authenticated using(user_id=auth.uid() or public.is_admin());

create or replace function public.purchase_product(p_product_id uuid)
returns uuid language plpgsql security definer set search_path=public
as $$
declare p public.products%rowtype; new_order uuid;
begin
  if auth.uid() is null then raise exception 'Vui lòng đăng nhập'; end if;
  select * into p from public.products where id=p_product_id and active=true;
  if not found then raise exception 'Sản phẩm không tồn tại hoặc đã ẩn'; end if;
  update public.profiles set balance=balance-p.price
   where id=auth.uid() and balance>=p.price;
  if not found then raise exception 'Số dư không đủ'; end if;
  insert into public.orders(user_id,product_id,product_name,amount)
   values(auth.uid(),p.id,p.name,p.price) returning id into new_order;
  return new_order;
end;
$$;

create or replace function public.admin_approve_topup(p_request_id uuid)
returns void language plpgsql security definer set search_path=public
as $$
declare r public.topup_requests%rowtype;
begin
  if not public.is_admin() then raise exception 'Không có quyền Admin'; end if;
  select * into r from public.topup_requests where id=p_request_id for update;
  if not found then raise exception 'Không tìm thấy yêu cầu'; end if;
  if r.status <> 'pending' then raise exception 'Yêu cầu đã được xử lý'; end if;
  update public.profiles set balance=balance+r.amount where id=r.user_id;
  update public.topup_requests set status='approved',reviewed_at=now() where id=r.id;
end;
$$;

revoke all on function public.purchase_product(uuid) from public;
grant execute on function public.purchase_product(uuid) to authenticated;
revoke all on function public.admin_approve_topup(uuid) from public;
grant execute on function public.admin_approve_topup(uuid) to authenticated;
