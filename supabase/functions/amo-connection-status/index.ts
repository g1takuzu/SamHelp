// Returns safe connection metadata for the authenticated SamHelp user.
const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "GET") return json({ error: "Method not allowed" }, 405);

  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!supabaseUrl || !anonKey || !serviceKey) return json({ error: "Server is not configured" }, 503);

  const authorization = req.headers.get("Authorization") || "";
  if (!authorization.startsWith("Bearer ")) return json({ error: "Authentication required" }, 401);
  const userResponse = await fetch(`${supabaseUrl}/auth/v1/user`, {
    headers: { apikey: anonKey, Authorization: authorization },
  });
  if (!userResponse.ok) return json({ error: "Invalid or expired SamHelp session" }, 401);
  const user = await userResponse.json();
  if (!user?.id) return json({ error: "Invalid user session" }, 401);

  const response = await fetch(
    `${supabaseUrl}/rest/v1/amo_connections?user_id=eq.${encodeURIComponent(user.id)}&select=account_subdomain,connected_at,last_error&limit=1`,
    { headers: { apikey: serviceKey, Authorization: `Bearer ${serviceKey}` } },
  );
  if (!response.ok) return json({ error: "Could not read integration status" }, 500);
  const rows = await response.json();
  const row = Array.isArray(rows) ? rows[0] : null;
  return json({
    connected: !!(row && row.connected_at && row.account_subdomain),
    account_subdomain: row?.account_subdomain || null,
    connected_at: row?.connected_at || null,
    last_error: row?.last_error || null,
  });
});
