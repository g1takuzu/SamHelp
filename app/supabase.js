/* SamHelp Cloud bridge — Supabase Auth + shared links only.
   Safe for the renderer: publishable key only; database RLS is authoritative. */
(function () {
  "use strict";
  var CONFIG = {
    url: "https://bkufmrrydwsmitwcqiky.supabase.co",
    publishableKey: "sb_publishable_oiT9ZYLWrpdHAOqK0XRcsA_Wet39Gc8"
  };
  var STORAGE_KEY = "samhelp_supabase_session_v1";
  var session = null;
  try { session = JSON.parse(localStorage.getItem(STORAGE_KEY) || "null"); } catch (_) {}

  function saveSession(value) {
    session = value || null;
    try {
      if (session) localStorage.setItem(STORAGE_KEY, JSON.stringify(session));
      else localStorage.removeItem(STORAGE_KEY);
    } catch (_) {}
  }
  function headers(extra) {
    var h = { "apikey": CONFIG.publishableKey, "Content-Type": "application/json" };
    if (session && session.access_token) h.Authorization = "Bearer " + session.access_token;
    Object.keys(extra || {}).forEach(function (k) { h[k] = extra[k]; });
    return h;
  }
  async function request(path, options, retry) {
    options = options || {};
    var response = await fetch(CONFIG.url + path, {
      method: options.method || "GET",
      headers: headers(options.headers),
      body: options.body === undefined ? undefined : JSON.stringify(options.body)
    });
    if (response.status === 401 && session && session.refresh_token && !retry) {
      await refresh();
      return request(path, options, true);
    }
    var raw = await response.text(), data = null;
    try { data = raw ? JSON.parse(raw) : null; } catch (_) { data = raw; }
    if (!response.ok) {
      var message = data && (data.msg || data.message || data.error_description || data.error) || "Supabase request failed (" + response.status + ")";
      throw new Error(message);
    }
    return data;
  }
  async function auth(path, body) {
    var response = await fetch(CONFIG.url + "/auth/v1/" + path, {
      method: "POST",
      headers: { "apikey": CONFIG.publishableKey, "Content-Type": "application/json" },
      body: JSON.stringify(body || {})
    });
    var raw = await response.text(), data = null;
    try { data = raw ? JSON.parse(raw) : null; } catch (_) { data = raw; }
    if (!response.ok) throw new Error(data && (data.msg || data.message || data.error_description) || "Ошибка авторизации (" + response.status + ")");
    if (data && data.access_token) saveSession(data);
    return data;
  }
  async function refresh() {
    if (!session || !session.refresh_token) throw new Error("Сессия завершена. Войдите снова.");
    var data = await auth("token?grant_type=refresh_token", { refresh_token: session.refresh_token });
    return data;
  }
  function currentSession() { return session ? { user: session.user || null, expires_at: session.expires_at || null } : null; }
  async function getUser() {
    if (!session || !session.access_token) return null;
    try {
      var user = await request("/auth/v1/user");
      session.user = user; saveSession(session); return user;
    } catch (_) { saveSession(null); return null; }
  }
  function authEmail(login) {
    var value = String(login || "").trim().toLowerCase();
    // Legacy compatibility: the existing administrator can still sign in with the email used before this change.
    return value.indexOf("@") >= 0 ? value : value + "@users.samhelp.invalid";
  }
  async function signUp(login, password, displayName) {
    var normalized = String(login || "").trim().toLowerCase();
    return auth("signup", {
      email: authEmail(normalized), password: password,
      data: { login: normalized, display_name: displayName }
    });
  }
  async function signIn(login, password) {
    return auth("token?grant_type=password", { email: authEmail(login), password: password });
  }
  async function signOut() {
    try { if (session && session.access_token) await request("/auth/v1/logout", { method: "POST" }); }
    finally { saveSession(null); }
  }
  async function roles() {
    var result = await request("/rest/v1/shared_editors?select=user_id&limit=1");
    var user = session && session.user;
    var editor = !!(user && result && result.some(function (x) { return x.user_id === user.id; }));
    var admins = await request("/rest/v1/shared_admins?select=user_id&limit=1");
    var admin = !!(user && admins && admins.some(function (x) { return x.user_id === user.id; }));
    return { editor: editor, admin: admin };
  }
  async function getSiteCustomizations() {
    return request("/rest/v1/rpc/get_site_customizations", { method: "POST", body: {} });
  }
  async function updateSiteCustomizations(config) {
    return request("/rest/v1/rpc/admin_update_site_customizations", {
      method: "POST", body: { new_config: config }
    });
  }
  async function listUsers() {
    return request("/rest/v1/rpc/admin_list_users", { method: "POST", body: {} });
  }
  async function setUserRole(userId, role) {
    return request("/rest/v1/rpc/admin_set_user_role", {
      method: "POST", body: { target_user_id: userId, new_role: role }
    });
  }
  function toRow(kind, item) {
    return {
      kind: kind, title: item.title || "", url: item.url || "", note: item.note || "",
      group_name: item.group || "", icon: item.icon || ""
    };
  }
  function fromRow(row) {
    return {
      id: row.id, title: row.title, url: row.url, note: row.note || "",
      group: row.group_name || "", icon: row.icon || "", _cloud: true
    };
  }
  async function listShared() {
    var rows = await request("/rest/v1/shared_links?select=*&order=created_at.asc");
    return { sheets: rows.filter(function (x) { return x.kind === "sheets"; }).map(fromRow),
      apps: rows.filter(function (x) { return x.kind === "apps"; }).map(fromRow) };
  }
  async function addShared(kind, item) {
    var rows = await request("/rest/v1/shared_links", { method: "POST",
      headers: { "Prefer": "return=representation" }, body: toRow(kind, item) });
    return fromRow(rows[0]);
  }
  async function updateShared(kind, id, item) {
    var rows = await request("/rest/v1/shared_links?id=eq." + encodeURIComponent(id) + "&kind=eq." + encodeURIComponent(kind),
      { method: "PATCH", headers: { "Prefer": "return=representation" }, body: toRow(kind, item) });
    if (!rows || !rows.length) throw new Error("Запись не найдена или нет прав на изменение");
    return fromRow(rows[0]);
  }
  async function deleteShared(kind, id) {
    await request("/rest/v1/shared_links?id=eq." + encodeURIComponent(id) + "&kind=eq." + encodeURIComponent(kind),
      { method: "DELETE" });
  }


  var realtimeSocket = null, realtimeHeartbeat = null, realtimeReconnect = null, realtimeStopped = true;
  function subscribeCloud(onChange) {
    realtimeStopped = false;
    function connect() {
      if (realtimeStopped || !session || !session.access_token || typeof WebSocket === "undefined") return;
      var user = session.user;
      if (!user || !user.id) return;
      var wsUrl = CONFIG.url.replace(/^https:/, "wss:").replace(/^http:/, "ws:") +
        "/realtime/v1/websocket?apikey=" + encodeURIComponent(CONFIG.publishableKey) + "&vsn=1.0.0";
      try { realtimeSocket = new WebSocket(wsUrl); } catch (_) {
        realtimeReconnect = setTimeout(connect, 4000); return;
      }
      realtimeSocket.onopen = function () {
        if (!realtimeSocket || realtimeSocket.readyState !== 1) return;
        realtimeSocket.send(JSON.stringify({
          topic: "realtime:public:samhelp",
          event: "phx_join",
          payload: {
            config: {
              broadcast: { ack: false, self: false },
              presence: { key: "" },
              postgres_changes: [
                { event: "*", schema: "public", table: "private_contacts", filter: "user_id=eq." + user.id },
                { event: "*", schema: "public", table: "shared_app_config" },
                { event: "*", schema: "public", table: "shared_links" }
              ]
            },
            access_token: session.access_token
          },
          ref: "1"
        }));
        if (realtimeHeartbeat) clearInterval(realtimeHeartbeat);
        realtimeHeartbeat = setInterval(function () {
          if (realtimeSocket && realtimeSocket.readyState === 1) {
            realtimeSocket.send(JSON.stringify({ topic: "phoenix", event: "heartbeat", payload: {}, ref: String(Date.now()) }));
          }
        }, 25000);
      };
      realtimeSocket.onmessage = function (event) {
        var message;
        try { message = JSON.parse(event.data); } catch (_) { return; }
        if (message && message.event === "postgres_changes" && typeof onChange === "function") {
          try { onChange(message.payload && (message.payload.data || message.payload)); } catch (e) { console.error("SamHelp realtime callback", e); }
        }
      };
      realtimeSocket.onclose = function () {
        if (realtimeHeartbeat) { clearInterval(realtimeHeartbeat); realtimeHeartbeat = null; }
        realtimeSocket = null;
        if (!realtimeStopped) realtimeReconnect = setTimeout(connect, 4000);
      };
      realtimeSocket.onerror = function () {
        try { if (realtimeSocket) realtimeSocket.close(); } catch (_) {}
      };
    }
    connect();
    return function () {
      realtimeStopped = true;
      if (realtimeReconnect) clearTimeout(realtimeReconnect);
      if (realtimeHeartbeat) clearInterval(realtimeHeartbeat);
      realtimeReconnect = realtimeHeartbeat = null;
      if (realtimeSocket) { try { realtimeSocket.close(); } catch (_) {} }
      realtimeSocket = null;
    };
  }

  // Private contacts: RLS is the security boundary; the owner is always taken from
  // the authenticated session, never from a contact object supplied by the UI.
  function currentUserId() {
    return session && session.user && session.user.id || null;
  }
  async function listPrivateContacts() {
    var userId = currentUserId();
    if (!userId) throw new Error("Для синхронизации контактов нужно войти в аккаунт");
    var rows = await request("/rest/v1/private_contacts?select=contact_id,data,updated_at&order=updated_at.asc");
    return (rows || []).map(function (row) {
      var item = row.data && typeof row.data === "object" ? row.data : {};
      item.id = row.contact_id;
      item.owner = userId;
      return item;
    });
  }
  async function upsertPrivateContact(contact) {
    var userId = currentUserId();
    if (!userId) throw new Error("Нет активной учётной записи");
    if (!contact || !contact.id) throw new Error("У контакта отсутствует ID");
    var data = JSON.parse(JSON.stringify(contact));
    data.owner = userId;
    var rows = await request("/rest/v1/private_contacts?on_conflict=user_id,contact_id", {
      method: "POST",
      headers: { "Prefer": "resolution=merge-duplicates,return=minimal" },
      body: { user_id: userId, contact_id: String(contact.id), data: data }
    });
    return rows;
  }
  async function upsertPrivateContacts(contacts) {
    var userId = currentUserId();
    if (!userId) throw new Error("Нет активной учётной записи");
    var rows = (contacts || []).filter(function (c) { return c && c.id; }).map(function (c) {
      var data = JSON.parse(JSON.stringify(c)); data.owner = userId;
      return { user_id: userId, contact_id: String(c.id), data: data };
    });
    if (!rows.length) return;
    await request("/rest/v1/private_contacts?on_conflict=user_id,contact_id", {
      method: "POST",
      headers: { "Prefer": "resolution=merge-duplicates,return=minimal" },
      body: rows
    });
  }
  async function deletePrivateContact(contactId) {
    if (!currentUserId()) throw new Error("Нет активной учётной записи");
    await request("/rest/v1/private_contacts?contact_id=eq." + encodeURIComponent(contactId), { method: "DELETE" });
  }
  async function getAmoConnectionStatus() {
    return request("/functions/v1/amo-connection-status");
  }
  async function getAmoContactStatus(phone, contactId) {
    return request("/functions/v1/amo-contact-status", {
      method: "POST", body: { phone: phone, samhelp_contact_id: contactId }
    });
  }
  async function getSharedAppConfig() {
    return request("/rest/v1/rpc/get_shared_app_config", { method: "POST", body: {} });
  }
  async function updateSharedAppConfig(config) {
    return request("/rest/v1/rpc/update_shared_app_config", {
      method: "POST", body: { new_config: config }
    });
  }

  window.SamHelpCloud = {
    configured: true, currentSession: currentSession, getUser: getUser,
    signUp: signUp, signIn: signIn, signOut: signOut, refresh: refresh, roles: roles,
    listUsers: listUsers, setUserRole: setUserRole,
    getSiteCustomizations: getSiteCustomizations, updateSiteCustomizations: updateSiteCustomizations,
    listShared: listShared, addShared: addShared, updateShared: updateShared, deleteShared: deleteShared,
    listPrivateContacts: listPrivateContacts, upsertPrivateContact: upsertPrivateContact,
    upsertPrivateContacts: upsertPrivateContacts, deletePrivateContact: deletePrivateContact,
    getSharedAppConfig: getSharedAppConfig, updateSharedAppConfig: updateSharedAppConfig,
    getAmoConnectionStatus: getAmoConnectionStatus, getAmoContactStatus: getAmoContactStatus,
    subscribeCloud: subscribeCloud
  };
})();
