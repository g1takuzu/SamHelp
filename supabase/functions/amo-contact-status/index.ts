// Read the current amoCRM deal status for one SamHelp contact.
// Status is read-only in SamHelp: this function never PATCHes a lead.
const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });

function fromB64(value: string) {
  return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}
function toB64(bytes: Uint8Array) {
  return btoa(String.fromCharCode(...bytes));
}
async function decrypt(value: string, keyText: string) {
  const raw = fromB64(keyText);
  if (raw.length !== 32) throw new Error("Invalid encryption key");
  const bytes = fromB64(value), iv = bytes.slice(0, 12), cipher = bytes.slice(12);
  const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher);
  return new TextDecoder().decode(plain);
}
async function sha256(value: string) { return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))), b => b.toString(16).padStart(2, "0")).join(""); }
async function encrypt(value: string, keyText: string) {
  const raw = fromB64(keyText);
  if (raw.length !== 32) throw new Error("Invalid encryption key");
  const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(value));
  const out = new Uint8Array(iv.length + cipher.byteLength);
  out.set(iv); out.set(new Uint8Array(cipher), iv.length);
  return toB64(out);
}
function normalizePhone(value: unknown) {
  let digits = String(value || "").replace(/\D/g, "");
  if (digits.length === 11 && digits.startsWith("8")) digits = "7" + digits.slice(1);
  return digits;
}
async function readJson(response: Response) {
  const text = await response.text();
  if (!text) return null;
  try { return JSON.parse(text); } catch { return { detail: text }; }
}
async function amoGet(origin: string, path: string, token: string) {
  const response = await fetch(origin + path, { headers: { Authorization: "Bearer " + token, Accept: "application/hal+json" } });
  const data = await readJson(response);
  if (!response.ok) throw new Error("amoCRM API " + response.status + ": " + String(data?.detail || data?.title || data?.message || "request failed"));
  return data;
}
function exactPhone(contact: any, target: string) {
  const fields = Array.isArray(contact?.custom_fields_values) ? contact.custom_fields_values : [];
  return fields.some((field: any) => {
    if (field?.field_code !== "PHONE") return false;
    return (field.values || []).some((item: any) => normalizePhone(item?.value) === target);
  });
}
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  const encryptionKey = Deno.env.get("AMO_TOKEN_ENCRYPTION_KEY");
  const redirectUri = Deno.env.get("AMO_REDIRECT_URI");
  if (!supabaseUrl || !anonKey || !serviceKey || !encryptionKey || !redirectUri) {
    return json({ error: "Server integration settings are incomplete" }, 503);
  }

  const authorization = req.headers.get("Authorization") || "";
  if (!authorization.startsWith("Bearer ")) return json({ error: "Authentication required" }, 401);
  const authResponse = await fetch(supabaseUrl + "/auth/v1/user", { headers: { apikey: anonKey, Authorization: authorization } });
  if (!authResponse.ok) return json({ error: "Invalid SamHelp session" }, 401);
  const user = await authResponse.json();
  if (!user?.id) return json({ error: "Invalid SamHelp user" }, 401);

  let body: any;
  try { body = await req.json(); } catch { return json({ error: "Invalid request body" }, 400); }
  const phone = normalizePhone(body?.phone);
  const samhelpContactId = String(body?.samhelp_contact_id || "").slice(0, 120);
  if (phone.length < 7 || phone.length > 16 || !samhelpContactId) {
    return json({ error: "A valid phone and SamHelp contact ID are required" }, 400);
  }

  const headers = { apikey: serviceKey, Authorization: "Bearer " + serviceKey };
  const connectionResponse = await fetch(
    supabaseUrl + "/rest/v1/amo_connections?user_id=eq." + encodeURIComponent(user.id) +
    "&select=id,account_subdomain,access_token_ciphertext,refresh_token_ciphertext,token_expires_at,client_id_ciphertext,client_secret_ciphertext,webhook_secret_ciphertext,webhook_registered_at&limit=1",
    { headers }
  );
  const connections = await readJson(connectionResponse);
  if (!connectionResponse.ok) return json({ error: "Could not read the user's amoCRM connection" }, 500);
  const connection = Array.isArray(connections) ? connections[0] : null;
  if (!connection?.connected_at && !connection?.access_token_ciphertext) return json({ connected: false, match: "not_connected" }, 200);
  if (!connection?.account_subdomain || !connection?.access_token_ciphertext ||
      !connection?.refresh_token_ciphertext || !connection?.client_id_ciphertext || !connection?.client_secret_ciphertext) {
    return json({ connected: false, error: "amoCRM connection is incomplete; reconnect the account" }, 409);
  }

  let accessToken: string, refreshToken: string, clientId: string, clientSecret: string;
  try {
    [accessToken, refreshToken, clientId, clientSecret] = await Promise.all([
      decrypt(connection.access_token_ciphertext, encryptionKey),
      decrypt(connection.refresh_token_ciphertext, encryptionKey),
      decrypt(connection.client_id_ciphertext, encryptionKey),
      decrypt(connection.client_secret_ciphertext, encryptionKey),
    ]);
  } catch {
    return json({ connected: false, error: "Could not decrypt amoCRM credentials; reconnect the account" }, 500);
  }

  const origin = "https://" + String(connection.account_subdomain).replace(/^https?:\/\//, "").replace(/\/$/, "");
  const expiry = connection.token_expires_at ? Date.parse(connection.token_expires_at) : 0;
  if (!expiry || expiry < Date.now() + 5 * 60 * 1000) {
    const refreshed = await fetch(origin + "/oauth2/access_token", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, grant_type: "refresh_token", refresh_token: refreshToken, redirect_uri: redirectUri })
    });
    const tokens = await readJson(refreshed);
    if (!refreshed.ok || !tokens?.access_token || !tokens?.refresh_token) {
      await fetch(supabaseUrl + "/rest/v1/amo_connections?id=eq." + encodeURIComponent(connection.id), {
        method: "PATCH", headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify({ last_error: "amoCRM token refresh failed; reconnect required" })
      });
      return json({ connected: false, error: "Срок доступа amoCRM истёк. Переподключите аккаунт." }, 409);
    }
    accessToken = tokens.access_token;
    refreshToken = tokens.refresh_token;
    const [accessCipher, refreshCipher] = await Promise.all([
      encrypt(accessToken, encryptionKey), encrypt(refreshToken, encryptionKey)
    ]);
    const updated = await fetch(supabaseUrl + "/rest/v1/amo_connections?id=eq." + encodeURIComponent(connection.id), {
      method: "PATCH", headers: { ...headers, "Content-Type": "application/json" },
      body: JSON.stringify({
        access_token_ciphertext: accessCipher, refresh_token_ciphertext: refreshCipher,
        token_expires_at: new Date(Date.now() + Number(tokens.expires_in || 86400) * 1000).toISOString(),
        last_error: null
      })
    });
    if (!updated.ok) return json({ error: "Could not store refreshed amoCRM tokens" }, 500);
  }

  let webhookEnabled = !!connection.webhook_registered_at;
  try {
    let webhookSecret = connection.webhook_secret_ciphertext
      ? await decrypt(connection.webhook_secret_ciphertext, encryptionKey)
      : "";
    if (!webhookSecret) {
      const random = crypto.getRandomValues(new Uint8Array(32));
      webhookSecret = btoa(String.fromCharCode(...random)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
      const [secretHash, secretCipher] = await Promise.all([
        sha256(webhookSecret), encrypt(webhookSecret, encryptionKey)
      ]);
      const stored = await fetch(supabaseUrl + "/rest/v1/amo_connections?id=eq." + encodeURIComponent(connection.id), {
        method: "PATCH", headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify({ webhook_secret_hash: secretHash, webhook_secret_ciphertext: secretCipher })
      });
      if (!stored.ok) throw new Error("Could not store webhook secret");
    }
    if (!webhookEnabled) {
      const destination = supabaseUrl + "/functions/v1/amo-webhook?key=" + encodeURIComponent(webhookSecret);
      const registration = await fetch(origin + "/api/v4/webhooks", {
        method: "POST", headers: { Authorization: "Bearer " + accessToken, "Content-Type": "application/json" },
        body: JSON.stringify({ destination, settings: ["status_lead"] })
      });
      if (registration.ok) {
        const saved = await fetch(supabaseUrl + "/rest/v1/amo_connections?id=eq." + encodeURIComponent(connection.id), {
          method: "PATCH", headers: { ...headers, "Content-Type": "application/json" },
          body: JSON.stringify({ webhook_registered_at: new Date().toISOString(), last_error: null })
        });
        webhookEnabled = saved.ok;
      } else {
        const detail = await readJson(registration);
        await fetch(supabaseUrl + "/rest/v1/amo_connections?id=eq." + encodeURIComponent(connection.id), {
          method: "PATCH", headers: { ...headers, "Content-Type": "application/json" },
          body: JSON.stringify({ last_error: "Webhook unavailable (administrator permission required): " + String(detail?.title || detail?.detail || registration.status) })
        });
      }
    }
  } catch (webhookError) {
    console.error("amoCRM webhook registration failed", webhookError);
  }

  try {
    const search = await amoGet(origin, "/api/v4/contacts?query=" + encodeURIComponent(phone) + "&with=leads&limit=50", accessToken);
    const contacts = (search?._embedded?.contacts || []).filter((contact: any) => exactPhone(contact, phone));
    if (!contacts.length) {
      await fetch(supabaseUrl + "/rest/v1/amo_contact_links?user_id=eq." + encodeURIComponent(user.id) +
        "&samhelp_contact_id=eq." + encodeURIComponent(samhelpContactId), { method: "DELETE", headers });
      return json({ connected: true, match: "not_found", phone, webhook_enabled: webhookEnabled });
    }

    const candidates: any[] = [];
    for (const contact of contacts) {
      let linked = contact?._embedded?.leads;
      if (!Array.isArray(linked)) {
        const detail = await amoGet(origin, "/api/v4/contacts/" + contact.id + "?with=leads", accessToken);
        linked = detail?._embedded?.leads || [];
      }
      for (const lead of linked) candidates.push({ ...lead, amo_contact_id: contact.id });
    }
    if (!candidates.length) {
      return json({ connected: true, match: "contact_without_deal", contact_id: contacts[0].id, contact_name: contacts[0].name, webhook_enabled: webhookEnabled });
    }

    candidates.sort((a, b) => Number(b.updated_at || b.created_at || 0) - Number(a.updated_at || a.created_at || 0));
    let lead = candidates[0];
    const matchedContactId = lead.amo_contact_id || contacts[0].id;
    if (!lead.status_id || !lead.pipeline_id) lead = { ...await amoGet(origin, "/api/v4/leads/" + lead.id, accessToken), amo_contact_id: matchedContactId };
    const [pipeline, statuses] = await Promise.all([
      amoGet(origin, "/api/v4/leads/pipelines/" + lead.pipeline_id, accessToken).catch(() => null),
      amoGet(origin, "/api/v4/leads/pipelines/" + lead.pipeline_id + "/statuses", accessToken).catch(() => null),
    ]);
    const status = (statuses?._embedded?.statuses || []).find((item: any) => String(item.id) === String(lead.status_id));
    const result = {
      connected: true, match: "found", phone,
      contact_id: lead.amo_contact_id || contacts[0].id,
      contact_name: contacts.find((x: any) => String(x.id) === String(lead.amo_contact_id || contacts[0].id))?.name || contacts[0].name,
      lead_id: lead.id, lead_name: lead.name || "",
      pipeline_id: lead.pipeline_id, pipeline_name: pipeline?.name || "",
      status_id: lead.status_id, status_name: status?.name || ("Статус #" + lead.status_id),
      status_color: status?.color || null,
      lead_updated_at: lead.updated_at || null,
      matching_contacts: contacts.length, matching_deals: candidates.length, webhook_enabled: webhookEnabled,
      deal_url: origin + "/leads/detail/" + lead.id
    };

    await fetch(supabaseUrl + "/rest/v1/amo_contact_links?on_conflict=user_id,samhelp_contact_id", {
      method: "POST",
      headers: { ...headers, "Content-Type": "application/json", Prefer: "resolution=merge-duplicates,return=minimal" },
      body: JSON.stringify({
        connection_id: connection.id, user_id: user.id, samhelp_contact_id: samhelpContactId,
        amo_contact_id: result.contact_id, amo_lead_id: result.lead_id,
        pipeline_id: result.pipeline_id, status_id: result.status_id,
        last_synced_at: new Date().toISOString(), last_sync_source: "amocrm"
      })
    });
    return json(result);
  } catch (error) {
    const message = error instanceof Error ? error.message : "amoCRM request failed";
    return json({ connected: true, error: message }, 502);
  }
});
