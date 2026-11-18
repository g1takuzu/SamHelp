// Starts a per-user amoCRM OAuth flow. Deploy with JWT verification enabled.
const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  const clientId = Deno.env.get("AMO_CLIENT_ID");
  const redirectUri = Deno.env.get("AMO_REDIRECT_URI");
  if (!supabaseUrl || !anonKey || !serviceKey || !clientId || !redirectUri) {
    return json({ error: "Integration is not configured on the server" }, 503);
  }

  const authorization = req.headers.get("Authorization") || "";
  if (!authorization.startsWith("Bearer ")) return json({ error: "Authentication required" }, 401);

  const userResponse = await fetch(`${supabaseUrl}/auth/v1/user`, {
    headers: { apikey: anonKey, Authorization: authorization },
  });
  if (!userResponse.ok) return json({ error: "Invalid or expired SamHelp session" }, 401);
  const user = await userResponse.json();
  if (!user?.id) return json({ error: "Invalid user session" }, 401);

  const random = new Uint8Array(32);
  crypto.getRandomValues(random);
  const state = btoa(String.fromCharCode(...random)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(state));
  const stateHash = Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("");

  const saved = await fetch(`${supabaseUrl}/rest/v1/amo_oauth_states`, {
    method: "POST",
    headers: {
      apikey: serviceKey,
      Authorization: `Bearer ${serviceKey}`,
      "Content-Type": "application/json",
      Prefer: "return=minimal",
    },
    body: JSON.stringify({
      state_hash: stateHash,
      user_id: user.id,
      expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
    }),
  });
  if (!saved.ok) return json({ error: "Could not start secure OAuth session" }, 500);

  const authorize = new URL("https://www.amocrm.ru/oauth");
  authorize.searchParams.set("client_id", clientId);
  authorize.searchParams.set("state", state);
  authorize.searchParams.set("mode", "post_message");
  return json({ authorization_url: authorize.toString(), expires_in: 600 });
});
