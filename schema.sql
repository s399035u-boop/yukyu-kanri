-- =====================================================================
--  有給管理アプリ  Supabase スキーマ（適用済み・記録用）
--  ※ このファイルの内容は Management API 経由ですでにDBに適用されています。
--
--  設計メモ:
--   - 承認フローなし：スタッフが登録した有給は即 approved でカレンダーに反映
--   - 有給の最小単位は1時間（1日=8時間換算、days は 0.125 刻み）
--   - 日付ルール（JST基準）:
--       登録 … start_date が今日以降のみ（スタッフ）
--       取消 … start_date が明日以降のみ（日付が来たら確定・削除不可）
--       管理者は req_admin_all で全操作可能（過去分の代理登録・修正用）
--   - 法定自動付与はクライアント側で実施（note='法定付与（自動）' が識別子）
--       入職6ヶ月後10日 → 以後1年ごと 11,12,14,16,18,20(上限)、時効2年
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. profiles : スタッフ情報 ＋ ロール
-- ---------------------------------------------------------------------
create table if not exists public.profiles (
  id         uuid primary key references auth.users(id) on delete cascade,
  email      text,
  full_name  text,
  role        text not null default 'staff' check (role in ('staff','admin')),
  hire_date   date,                          -- 入職日（法定自動付与の起点）
  auto_grant  boolean not null default true, -- 法定自動付与の有効/無効
  birth_month int check (birth_month between 1 and 12), -- 誕生月（誕生日休2日を毎年自動付与）
  birth_day   int check (birth_day between 1 and 31),   -- 誕生日（カレンダーに自動表示）
  active      boolean not null default true,
  created_at timestamptz not null default now()
);

-- ---------------------------------------------------------------------
-- 2. leave_grants : 有給の付与記録
-- ---------------------------------------------------------------------
create table if not exists public.leave_grants (
  id           uuid primary key default gen_random_uuid(),
  user_id      uuid not null references public.profiles(id) on delete cascade,
  days         numeric(6,3) not null,        -- 1時間 = 0.125日
  granted_date date not null default current_date,
  expires_date date,
  note         text,                         -- '法定付与（自動）'/'誕生日休（自動）' = 自動付与
  kind         text not null default 'paid'
               check (kind in ('paid','birthday','comp')), -- 有給/誕生日休/代休
  created_at   timestamptz not null default now()
);

-- ---------------------------------------------------------------------
-- 3. leave_requests : 有給の取得記録（承認フローなし、常に approved）
-- ---------------------------------------------------------------------
create table if not exists public.leave_requests (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null references public.profiles(id) on delete cascade,
  start_date  date not null,
  end_date    date not null,
  days        numeric(6,3) not null,         -- 1時間 = 0.125日
  reason      text,
  leave_type  text not null default 'day'
              check (leave_type in ('day','half','hour')),  -- 取得単位
  half_period text check (half_period in ('am','pm')),      -- 半休: 午前/午後
  start_time  time,                                          -- 時間単位: 開始時刻
  end_time    time,                                          -- 時間単位: 終了時刻
  kind        text not null default 'paid'
              check (kind in ('paid','birthday','comp')),   -- 有給/誕生日休/代休
  status      text not null default 'pending'
              check (status in ('pending','approved','rejected')),
  reviewed_by uuid references public.profiles(id),
  reviewed_at timestamptz,
  created_at  timestamptz not null default now()
);

-- ---------------------------------------------------------------------
-- 4. events : 共有予定（診療時間変更・ミーティング等、全員が読み書き削除可）
-- ---------------------------------------------------------------------
create table if not exists public.events (
  id         uuid primary key default gen_random_uuid(),
  title      text not null,
  event_date date not null,
  created_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now()
);

-- ---------------------------------------------------------------------
-- 5. is_admin() : 管理者判定（SECURITY DEFINER でRLSループ回避）
-- ---------------------------------------------------------------------
create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and role = 'admin'
  );
$$;

-- ---------------------------------------------------------------------
-- 6. 新規アカウント作成時に profiles 行を自動作成
-- ---------------------------------------------------------------------
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, email, full_name)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data->>'full_name', new.email)
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- =====================================================================
--  Row Level Security
-- =====================================================================

-- ----- profiles -----
alter table public.profiles enable row level security;

drop policy if exists profiles_select on public.profiles;
create policy profiles_select on public.profiles
  for select using (auth.uid() is not null);   -- 共有カレンダーで氏名表示のため全員閲覧可

drop policy if exists profiles_update_admin on public.profiles;
create policy profiles_update_admin on public.profiles
  for update using (public.is_admin()) with check (public.is_admin());

drop policy if exists profiles_update_self on public.profiles;
create policy profiles_update_self on public.profiles
  for update using (id = auth.uid())
  with check (id = auth.uid() and role = (select role from public.profiles where id = auth.uid()));

-- ----- leave_grants -----
alter table public.leave_grants enable row level security;

drop policy if exists grants_select on public.leave_grants;
create policy grants_select on public.leave_grants
  for select using (user_id = auth.uid() or public.is_admin());

drop policy if exists grants_admin_write on public.leave_grants;
create policy grants_admin_write on public.leave_grants
  for all using (public.is_admin()) with check (public.is_admin());

-- ----- leave_requests -----
alter table public.leave_requests enable row level security;

-- 閲覧: 本人 / 承認済み(=共有カレンダー用に全員) / 管理者
drop policy if exists req_select on public.leave_requests;
create policy req_select on public.leave_requests
  for select using (user_id = auth.uid() or status = 'approved' or public.is_admin());

-- 登録: 本人・approved・今日以降のみ（JST）
drop policy if exists req_insert_self on public.leave_requests;
create policy req_insert_self on public.leave_requests
  for insert with check (
    user_id = auth.uid()
    and status = 'approved'
    and start_date >= (now() at time zone 'Asia/Tokyo')::date
  );

-- 取消: 本人・未来日のみ（日付が来たら確定）
drop policy if exists req_delete_self on public.leave_requests;
create policy req_delete_self on public.leave_requests
  for delete using (
    user_id = auth.uid()
    and start_date > (now() at time zone 'Asia/Tokyo')::date
  );

-- 管理者: 全操作（過去分の代理登録・削除を含む）
drop policy if exists req_admin_all on public.leave_requests;
create policy req_admin_all on public.leave_requests
  for all using (public.is_admin()) with check (public.is_admin());

-- ----- events -----
alter table public.events enable row level security;

drop policy if exists events_select on public.events;
create policy events_select on public.events
  for select using (auth.uid() is not null);

drop policy if exists events_insert on public.events;
create policy events_insert on public.events
  for insert with check (auth.uid() is not null);

drop policy if exists events_delete on public.events;
create policy events_delete on public.events
  for delete using (auth.uid() is not null);

-- =====================================================================
--  管理者用RPC（SECURITY DEFINER・is_admin()でガード）
--  クライアントはanonキーのままRPC経由で認証ユーザーの作成/削除が可能
-- =====================================================================

-- 新規スタッフ作成：auth.users + auth.identities を作成（bcryptパスワード）、
-- handle_new_userトリガでprofiles作成 → 追加項目を更新
--   ※ auth.identities.email は生成列のため挿入しない
create or replace function public.admin_create_staff(
  p_email text, p_password text, p_full_name text,
  p_hire_date date default null, p_birth_month int default null,
  p_birth_day int default null, p_auto_grant boolean default true
) returns uuid
language plpgsql security definer set search_path = 'public'
as $$
declare new_id uuid := gen_random_uuid();
begin
  if not public.is_admin() then raise exception '管理者権限が必要です'; end if;
  if coalesce(p_full_name,'') = '' then raise exception '氏名を入力してください'; end if;
  if p_email is null or p_email !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then
    raise exception 'メールアドレスの形式が正しくありません'; end if;
  if p_password is null or length(p_password) < 8 then
    raise exception 'パスワードは8文字以上にしてください'; end if;
  if exists (select 1 from auth.users where lower(email) = lower(p_email)) then
    raise exception 'このメールアドレスは既に使われています'; end if;

  insert into auth.users (
    instance_id, id, aud, role, email, encrypted_password,
    email_confirmed_at, created_at, updated_at,
    raw_app_meta_data, raw_user_meta_data,
    confirmation_token, recovery_token, email_change_token_new, email_change
  ) values (
    '00000000-0000-0000-0000-000000000000', new_id, 'authenticated', 'authenticated',
    lower(p_email), extensions.crypt(p_password, extensions.gen_salt('bf')),
    now(), now(), now(),
    '{"provider":"email","providers":["email"]}'::jsonb,
    jsonb_build_object('full_name', p_full_name, 'email_verified', true),
    '', '', '', ''
  );
  insert into auth.identities (
    provider_id, user_id, identity_data, provider, last_sign_in_at, created_at, updated_at
  ) values (
    new_id::text, new_id,
    jsonb_build_object('sub', new_id::text, 'email', lower(p_email),
                       'email_verified', false, 'phone_verified', false),
    'email', now(), now(), now()
  );
  update public.profiles set
    full_name = p_full_name, hire_date = p_hire_date,
    birth_month = p_birth_month, birth_day = p_birth_day,
    role = 'staff', auto_grant = coalesce(p_auto_grant, true), active = true
  where id = new_id;
  return new_id;
end;
$$;
grant execute on function public.admin_create_staff(text,text,text,date,int,int,boolean) to authenticated;

-- スタッフ削除：auth.users削除 → profiles/grants/requests は on delete cascade
create or replace function public.admin_delete_staff(p_user_id uuid)
returns void language plpgsql security definer set search_path = 'public'
as $$
begin
  if not public.is_admin() then raise exception '管理者権限が必要です'; end if;
  if p_user_id = auth.uid() then raise exception '自分自身のアカウントは削除できません'; end if;
  if exists (select 1 from public.profiles where id = p_user_id and role = 'admin') then
    raise exception '管理者アカウントは削除できません'; end if;
  if not exists (select 1 from public.profiles where id = p_user_id) then
    raise exception '対象のスタッフが見つかりません'; end if;
  delete from auth.users where id = p_user_id;
end;
$$;
grant execute on function public.admin_delete_staff(uuid) to authenticated;
