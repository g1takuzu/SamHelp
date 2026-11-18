// Receives amoCRM lead-status webhooks and invalidates the matching private SamHelp contact cache.
function hex(bytes: Uint8Array) {
  return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}
async function sha256(value: string) {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))));
}
function equalConstantTime(a: string, b: string) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

Deno.serve(async (req) => {
  if (req.method !== "POST") return json({ error: "POST required" }, 405);
  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!supabaseUrl || !serviceKey) return json({ error: "Server not configured" }, 503);
  const secret = new URL(req.url).searchParams.get("key") || "";
  if (secret.length < 32 || secret.length > 256) return json({ error: "Unauthorized" }, 401);
  const secretHash = await sha256(secret);
  const headers = { apikey: serviceKey, Authorization: "Bearer " + serviceKey };
  const connectionResponse = await fetch(
    supabaseUrl + "/rest/v1/amo_connections?webhook_secret_hash=eq." + encodeURIComponent(secretHash) +
    "&select=id,user_id,account_subdomain&limit=1", { headers }
  );
  const connections = await connectionResponse.json().catch(() => []);
  if (!connectionResponse.ok || !Array.isArray(connections) || connections.length !== 1) return json({ error: "Unauthorized" }, 401);
  const connection = connections[0];

  let fields = new URLSearchParams();
  const contentType = req.headers.get("content-type") || "";
  if (contentType.includes("application/x-www-form-urlencoded") || contentType.includes("multipart/form-data")) {
    const form = await req.formData();
    form.forEach((value, key) => { fields.append(key, String(value)); });
  } else {
    const raw = await req.text();
    try {
      const parsed = JSON.parse(raw);
      for (const [key, value] of Object.entries(parsed || {})) fields.append(key, String(value));
    } catch { fields = new URLSearchParams(raw); }
  }

  const changes = new Map<string, { pipelineId: string; statusId: string }>();
  for (const [key, value] of fields.entries()) {
    const match = key.match(/^leads\[status\]\[(\d+)\]\[(id|pipeline_id|status_id)\]$/);
    if (!match) continue;
    const index = match[1], field = match[2];
    const item = changes.get(index) || { pipelineId: "", statusId: "" };
    if (field === "pipeline_id") item.pipelineId = value;
    if (field === "status_id") item.statusId = value;
    if (field === "id") (item as any).leadId = value;
    changes.set(index, item);
  }
  let processed = 0;
  for (const item of changes.values()) {
    const leadId = String((item as any).leadId || "");
    if (!leadId || !item.statusId) continue;
    const linksResponse = await fetch(
      supabaseUrl + "/rest/v1/amo_contact_links?connection_id=eq." + encodeURIComponent(connection.id) +
      "&amo_lead_id=eq." + encodeURIComponent(leadId) +
      "&select=user_id,samhelp_contact_id,amo_lead_id", { headers }
    );
    const links = await linksResponse.json().catch(() => []);
    if (!linksResponse.ok || !Array.isArray(links)) continue;
    for (const link of links) {
      await fetch(supabaseUrl + "/rest/v1/amo_contact_links?user_id=eq." + encodeURIComponent(link.user_id) +
        "&samhelp_contact_id=eq." + encodeURIComponent(link.samhelp_contact_id), {
        method: "PATCH", headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify({
          pipeline_id: item.pipelineId ? Number(item.pipelineId) : null,
          status_id: Number(item.statusId),
          last_synced_at: new Date().toISOString(),
          last_sync_source: "amocrm"
        })
      });
      const contactUrl = supabaseUrl + "/rest/v1/private_contacts?user_id=eq." + encodeURIComponent(link.user_id) +
        "&contact_id=eq." + encodeURIComponent(link.samhelp_contact_id) + "&select=data";
      const contactResponse = await fetch(contactUrl, { headers });
      const contactRows = await contactResponse.json().catch(() => []);
      if (!contactResponse.ok || !Array.isArray(contactRows) || !contactRows[0]?.data) continue;
      const data = contactRows[0].data;
      // Signal the desktop client to immediately re-read the authoritative status from amoCRM.
      data.amoStatusCheckedAt = 0;
      data.updated = Date.now();
      await fetch(supabaseUrl + "/rest/v1/private_contacts?user_id=eq." + encodeURIComponent(link.user_id) +
        "&contact_id=eq." + encodeURIComponent(link.samhelp_contact_id), {
        method: "PATCH", headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify({ data })
      });
      processed++;
    }
  }
  return json({ ok: true, processed });
});
