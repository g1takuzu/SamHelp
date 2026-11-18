// Receives amoCRM's external-integration webhook. Deploy with verify_jwt=false.
// The unpredictable one-time state binds the credentials to the SamHelp user session.
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
function fromB64(value: string) { return Uint8Array.from(atob(value), c => c.charCodeAt(0)); }
function b64(bytes: Uint8Array) { return btoa(String.fromCharCode(...bytes)); }
async function encrypt(value: string, keyText: string) {
  const raw = fromB64(keyText);
  if (raw.length !== 32) throw new Error("Invalid encryption key");
  const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(value));
  const out = new Uint8Array(iv.length + cipher.byteLength); out.set(iv); out.set(new Uint8Array(cipher), iv.length);
  return b64(out);
}
async function sha256(value: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("");
}
Deno.serve(async (req) => {
  if (req.method !== "POST") return json({ error: "POST required" }, 405);
  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  const encryptionKey = Deno.env.get("AMO_TOKEN_ENCRYPTION_KEY");
  if (!supabaseUrl || !serviceKey || !encryptionKey) return json({ error: "Server not configured" }, 503);
  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return json({ error: "Invalid JSON payload" }, 400); }
  const clientId = typeof body.client_id === "string" ? body.client_id : "";
  const clientSecret = typeof body.client_secret === "string" ? body.client_secret : "";
  const state = typeof body.state === "string" ? body.state : "";
  if (!clientId || !clientSecret || !state || clientId.length > 512 || clientSecret.length > 2048 || state.length > 256) {
    return json({ error: "Missing or invalid integration credentials/state" }, 400);
  }
  const hash = await sha256(state);
  const query = `${supabaseUrl}/rest/v1/amo_oauth_states?state_hash=eq.${hash}&consumed=eq.false&expires_at=gt.${encodeURIComponent(new Date().toISOString())}&select=state_hash`;
  const found = await fetch(query, { headers: { apikey: serviceKey, Authorization: `Bearer ${serviceKey}` } });
  const rows = await found.json().catch(() => []);
  if (!found.ok || !Array.isArray(rows) || rows.length !== 1) return json({ error: "Unknown, expired, or already-used state" }, 400);
  const [idCipher, secretCipher] = await Promise.all([encrypt(clientId, encryptionKey), encrypt(clientSecret, encryptionKey)]);
  const saved = await fetch(`${supabaseUrl}/rest/v1/amo_oauth_states?state_hash=eq.${hash}&consumed=eq.false&secrets_received_at=is.null`, {
    method: "PATCH",
    headers: { apikey: serviceKey, Authorization: `Bearer ${serviceKey}`, "Content-Type": "application/json", Prefer: "return=representation" },
    body: JSON.stringify({ client_id_ciphertext: idCipher, client_secret_ciphertext: secretCipher, secrets_received_at: new Date().toISOString() })
  });
  const updated = await saved.json().catch(() => []);
  if (!saved.ok || !Array.isArray(updated) || updated.length !== 1) return json({ error: "Credentials could not be bound to this session" }, 409);
  return json({ ok: true });
});
