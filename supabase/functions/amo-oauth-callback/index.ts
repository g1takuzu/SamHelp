// OAuth callback for amoCRM external integrations. Deploy with verify_jwt=false.
const html = (title: string, message: string, ok: boolean) => new Response(
  `<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><body style="font:16px system-ui;max-width:560px;margin:12vh auto;padding:24px;color:#20212a"><h2>${title}</h2><p>${message}</p><p>Можно закрыть эту вкладку и вернуться в SamHelp.</p></body></html>`,
  { status: ok ? 200 : 400, headers: { "Content-Type": "text/html; charset=utf-8" } },
);
function fromB64(value: string) { return Uint8Array.from(atob(value), c => c.charCodeAt(0)); }
function b64(bytes: Uint8Array) { return btoa(String.fromCharCode(...bytes)); }
async function decrypt(value: string, keyText: string) {
  const raw = fromB64(keyText); if (raw.length !== 32) throw new Error("Invalid encryption key");
  const bytes = fromB64(value); const iv = bytes.slice(0, 12); const cipher = bytes.slice(12);
  const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher);
  return new TextDecoder().decode(plain);
}
async function encrypt(value: string, keyText: string) {
  const raw = fromB64(keyText); const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(value));
  const out = new Uint8Array(iv.length + cipher.byteLength); out.set(iv); out.set(new Uint8Array(cipher), iv.length); return b64(out);
}
async function sha256(value: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("");
}
Deno.serve(async (req) => {
  if (req.method !== "GET") return html("Ошибка подключения", "Ожидался OAuth callback.", false);
  const url = new URL(req.url), code = url.searchParams.get("code"), state = url.searchParams.get("state"), referer = url.searchParams.get("referer");
  if (!code || !state || !referer) return html("Не удалось подключить amoCRM", "Не хватает параметров. Вернитесь в SamHelp и повторите подключение.", false);
  const supabaseUrl = Deno.env.get("SUPABASE_URL"), serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY"), encryptionKey = Deno.env.get("AMO_TOKEN_ENCRYPTION_KEY"), redirectUri = Deno.env.get("AMO_REDIRECT_URI");
  if (!supabaseUrl || !serviceKey || !encryptionKey || !redirectUri) return html("Интеграция не настроена", "Проверьте серверные секреты Supabase.", false);
  let accountUrl: URL;
  try {
    accountUrl = new URL(referer.startsWith("http") ? referer : `https://${referer}`);
    if (!/^([a-z0-9-]+\.)?amocrm\.(ru|com)$/i.test(accountUrl.hostname)) throw new Error("Bad host");
  } catch { return html("Ошибка подключения", "Некорректный адрес аккаунта amoCRM.", false); }

  const hash = await sha256(state);
  const stateUrl = `${supabaseUrl}/rest/v1/amo_oauth_states?state_hash=eq.${hash}&consumed=eq.false&expires_at=gt.${encodeURIComponent(new Date().toISOString())}&select=user_id,client_id_ciphertext,client_secret_ciphertext,secrets_received_at`;
  const read = await fetch(stateUrl, { headers: { apikey: serviceKey, Authorization: `Bearer ${serviceKey}` } });
  const rows = await read.json().catch(() => []);
  if (!read.ok || !Array.isArray(rows) || rows.length !== 1 || !rows[0].secrets_received_at || !rows[0].client_id_ciphertext || !rows[0].client_secret_ciphertext) {
    return html("Не найдены ключи интеграции", "amoCRM не передала ключи внешней интеграции. Начните подключение заново.", false);
  }
  const consume = await fetch(`${supabaseUrl}/rest/v1/amo_oauth_states?state_hash=eq.${hash}&consumed=eq.false&secrets_received_at=not.is.null`, {
    method: "PATCH", headers: { apikey: serviceKey, Authorization: `Bearer ${serviceKey}`, "Content-Type": "application/json", Prefer: "return=representation" }, body: JSON.stringify({ consumed: true })
  });
  const consumed = await consume.json().catch(() => []);
  if (!consume.ok || !Array.isArray(consumed) || consumed.length !== 1) return html("Ссылка уже использована", "Повторный callback отклонён. Начните подключение заново.", false);

  let clientId: string, clientSecret: string;
  try {
    [clientId, clientSecret] = await Promise.all([decrypt(rows[0].client_id_ciphertext, encryptionKey), decrypt(rows[0].client_secret_ciphertext, encryptionKey)]);
  } catch { return html("Ошибка ключей", "Не удалось расшифровать ключи интеграции.", false); }
  const tokenResponse = await fetch(`${accountUrl.origin}/oauth2/access_token`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, grant_type: "authorization_code", code, redirect_uri: redirectUri })
  });
  const tokens = await tokenResponse.json().catch(() => null);
  if (!tokenResponse.ok || !tokens?.access_token || !tokens?.refresh_token) return html("Не удалось получить доступ", "amoCRM отклонила авторизацию. Повторите подключение.", false);
  const accountResponse = await fetch(`${accountUrl.origin}/api/v4/account`, { headers: { Authorization: `Bearer ${tokens.access_token}` } });
  const account = await accountResponse.json().catch(() => null);
  if (!accountResponse.ok || !account?.id) return html("Не удалось определить аккаунт", "Не удалось проверить аккаунт amoCRM.", false);
  const [accessCipher, refreshCipher, idCipher, secretCipher] = await Promise.all([
    encrypt(tokens.access_token, encryptionKey), encrypt(tokens.refresh_token, encryptionKey),
    encrypt(clientId, encryptionKey), encrypt(clientSecret, encryptionKey)
  ]);
  const saved = await fetch(`${supabaseUrl}/rest/v1/amo_connections?on_conflict=user_id`, {
    method: "POST", headers: { apikey: serviceKey, Authorization: `Bearer ${serviceKey}`, "Content-Type": "application/json", Prefer: "resolution=merge-duplicates,return=minimal" },
    body: JSON.stringify({
      user_id: rows[0].user_id, account_id: account.id, account_subdomain: accountUrl.hostname,
      client_id_ciphertext: idCipher, client_secret_ciphertext: secretCipher,
      access_token_ciphertext: accessCipher, refresh_token_ciphertext: refreshCipher,
      token_expires_at: new Date(Date.now() + Number(tokens.expires_in || 86400) * 1000).toISOString(),
      connected_at: new Date().toISOString(), last_error: null,
      webhook_secret_hash: null, webhook_secret_ciphertext: null,
      webhook_registered_at: null, webhook_attempted_at: null
    })
  });
  if (!saved.ok) return html("Не удалось сохранить подключение", "Не удалось безопасно сохранить подключение. Обратитесь к администратору SamHelp.", false);
  return html("amoCRM подключена", "Аккаунт успешно подключён к вашему профилю SamHelp.", true);
});
