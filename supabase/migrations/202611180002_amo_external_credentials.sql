-- Add per-account OAuth client credentials for amoCRM external integrations.
alter table public.amo_connections
  add column if not exists client_id_ciphertext text,
  add column if not exists client_secret_ciphertext text;
alter table public.amo_oauth_states
  add column if not exists client_id_ciphertext text,
  add column if not exists client_secret_ciphertext text,
  add column if not exists secrets_received_at timestamptz;
