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

  window.SamHelpCloud = {
    configured: true, currentSession: currentSession, getUser: getUser,
    signUp: signUp, signIn: signIn, signOut: signOut, refresh: refresh, roles: roles,
    listUsers: listUsers, setUserRole: setUserRole,
    getSiteCustomizations: getSiteCustomizations, updateSiteCustomizations: updateSiteCustomizations,
    listShared: listShared, addShared: addShared, updateShared: updateShared, deleteShared: deleteShared
  };
})();
