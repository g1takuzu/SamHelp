-- Encrypted per-account webhook secret used to authenticate amoCRM status callbacks.
alter table public.amo_connections
  add column if not exists webhook_secret_ciphertext text;
