// OAuth callback. Deploy with verify_jwt=false; state is validated and consumed once.
const html = (title: string, message: string, ok: boolean) => new Response(
  `<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><body style="font:16px system-ui;max-width:560px;margin:12vh auto;padding:24px;color:#20212a"><h2>${title}</h2><p>${message}</p><p>Можно закрыть эту вкладку и вернуться в SamHelp.</p></body></html>`,
  { status: ok ? 200 : 400, headers: { "Content-Type": "text/html; charset=utf-8" } },
);
function b64(bytes: Uint8Array) {
  return btoa(String.fromCharCode(...bytes));
}
function fromB64(value: string) {
  return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}
async function encryptToken(value: string, keyText: string) {
  const raw = fromB64(keyText);
  if (raw.length !== 32) throw new Error("AMO_TOKEN_ENCRYPTION_KEY must be base64 for exactly 32 bytes");
  const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(value));
  const combined = new Uint8Array(iv.length + encrypted.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(encrypted), iv.length);
  return b64(combined);
}
async function sha256(value: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("");
}
Deno.serve(async (req) => {
  if (req.method !== "GET") return html("Ошибка подключения", "Ожидался OAuth callback.", false);
  const url = new URL(req.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const referer = url.searchParams.get("referer");
  if (!code || !state || !referer) return html("Не удалось подключить amoCRM", "В callback не хватает параметров авторизации. Вернитесь в SamHelp и повторите подключение.", false);

  const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
  const clientId = Deno.env.get("AMO_CLIENT_ID")!;
  const clientSecret = Deno.env.get("AMO_CLIENT_SECRET")!;
  const redirectUri = Deno.env.get("AMO_REDIRECT_URI")!;
  const encryptionKey = Deno.env.get("AMO_TOKEN_ENCRYPTION_KEY")!;
  if (!supabaseUrl || !serviceKey || !clientId || !clientSecret || !redirectUri || !encryptionKey) {
    return html("Интеграция не настроена", "Администратору SamHelp нужно настроить серверные секреты Supabase.", false);
  }

  let accountUrl: URL;
  try {
    accountUrl = new URL(referer.startsWith("http") ? referer : `https://${referer}`);
    if (!/^([a-z0-9-]+\.)?amocrm\.(ru|com)$/i.test(accountUrl.hostname)) throw new Error("Unexpected amoCRM host");
  } catch {
    return html("Ошибка подключения", "amoCRM вернула некорректный адрес аккаунта.", false);
  }

  const stateHash = await sha256(state);
  const stateResponse = await fetch(
    `${supabaseUrl}/rest/v1/amo_oauth_states?state_hash=eq.${stateHash}&consumed=eq.false&expires_at=gt.${encodeURIComponent(new Date().toISOString())}&select=user_id`,
    { headers: { apikey: serviceKey, Authorization: `Bearer ${serviceKey}` } },
  );
  if (!stateResponse.ok) return html("Ошибка подключения", "Не удалось проверить защищённую OAuth-сессию.", false);
  const stateRows = await stateResponse.json();
  if (!Array.isArray(stateRows) || stateRows.length !== 1) return html("Ссылка устарела", "Сессия подключения уже использована или истекла. Начните подключение заново из SamHelp.", false);
  const userId = stateRows[0].user_id;

  const consume = await fetch(
    `${supabaseUrl}/rest/v1/amo_oauth_states?state_hash=eq.${stateHash}&consumed=eq.false&expires_at=gt.${encodeURIComponent(new Date().toISOString())}`,
    {
      method: "PATCH",
      headers: { apikey: serviceKey, Authorization: `Bearer ${serviceKey}`, "Content-Type": "application/json", Prefer: "return=representation" },
      body: JSON.stringify({ consumed: true }),
    },
  );
  const consumedRows = await consume.json().catch(() => []);
  if (!consume.ok || !Array.isArray(consumedRows) || consumedRows.length !== 1) return html("Ссылка уже использована", "Повторный OAuth callback отклонён. Запустите подключение заново.", false);

  const tokenResponse = await fetch(`${accountUrl.origin}/oauth2/access_token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
    }),
  });
  const tokens = await tokenResponse.json().catch(() => null);
  if (!tokenResponse.ok || !tokens?.access_token || !tokens?.refresh_token) {
    return html("Не удалось получить доступ", "amoCRM не приняла код авторизации. Проверьте настройки интеграции и повторите подключение.", false);
  }

  const accountResponse = await fetch(`${accountUrl.origin}/api/v4/account`, {
    headers: { Authorization: `Bearer ${tokens.access_token}` },
  });
  const account = await accountResponse.json().catch(() => null);
  if (!accountResponse.ok || !account?.id) return html("Не удалось определить аккаунт", "Авторизация прошла, но SamHelp не смог проверить аккаунт amoCRM.", false);

  const [accessCipher, refreshCipher] = await Promise.all([
    encryptToken(tokens.access_token, encryptionKey),
    encryptToken(tokens.refresh_token, encryptionKey),
  ]);
  const saved = await fetch(`${supabaseUrl}/rest/v1/amo_connections?on_conflict=user_id`, {
    method: "POST",
    headers: {
      apikey: serviceKey,
      Authorization: `Bearer ${serviceKey}`,
      "Content-Type": "application/json",
      Prefer: "resolution=merge-duplicates,return=minimal",
    },
    body: JSON.stringify({
      user_id: userId,
      account_id: account.id,
      account_subdomain: accountUrl.hostname,
      access_token_ciphertext: accessCipher,
      refresh_token_ciphertext: refreshCipher,
      token_expires_at: new Date(Date.now() + Number(tokens.expires_in || 86400) * 1000).toISOString(),
      connected_at: new Date().toISOString(),
      last_error: null,
    }),
  });
  if (!saved.ok) return html("Не удалось сохранить подключение", "Авторизация прошла, но безопасное сохранение подключения завершилось ошибкой. Обратитесь к администратору.", false);
  return html("amoCRM подключена", "Аккаунт успешно подключён к вашему профилю SamHelp.", true);
});
