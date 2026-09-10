const crypto = require("crypto");
const admin = require("firebase-admin");

const REQUIREMENTS = Object.freeze({ 6: 1, 12: 2, 24: 3, 30: 4 });
const SESSION_TTL = 15 * 60 * 1000;
const KEY_PREFIX = "ZNEXUS-";
const AD_PROVIDER_BASE_URL = process.env.AD_PROVIDER_BASE_URL || "https://link-hub.net/6768455/qSE1FKce4SS7";
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || "https://keyzsystem.vercel.app").replace(/\/$/, "");
const recentRequests = new Map();

function json(res, status, payload) {
  res.status(status);
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.end(JSON.stringify(payload));
}

function getRoute(req) {
  const raw = new URL(req.url || "/", "https://placeholder.local").pathname;
  return raw.replace(/^\/api\/?/, "").replace(/^\/+|\/+$/g, "");
}

function getQuery(req) {
  return new URL(req.url || "/", "https://placeholder.local").searchParams;
}

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  return String(forwarded || req.headers["x-real-ip"] || "unknown").split(",")[0].trim().slice(0, 80);
}

function rateLimit(req, key, max = 30, windowMs = 60_000) {
  const now = Date.now();
  const ip = getClientIp(req);
  const id = `${key}:${ip}`;
  const item = recentRequests.get(id) || { count: 0, reset: now + windowMs };
  if (now > item.reset) { item.count = 0; item.reset = now + windowMs; }
  item.count++;
  recentRequests.set(id, item);
  if (recentRequests.size > 5000) {
    for (const [k, v] of recentRequests) if (v.reset < now) recentRequests.delete(k);
  }
  return item.count <= max;
}

function getAdmin() {
  if (admin.apps.length) return admin.app();
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  const databaseURL = process.env.FIREBASE_DATABASE_URL;
  if (!raw || !databaseURL) throw new Error("Firebase del servidor no está configurado.");
  const serviceAccount = JSON.parse(raw);
  return admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL
  });
}

async function readBody(req) {
  if (req.body && typeof req.body === "object") return req.body;
  return {};
}

function validDeviceId(deviceId) {
  return /^HWID-[A-Z0-9]{24}$/.test(deviceId);
}

async function getSession(db, id) {
  if (!/^[a-f0-9-]{20,100}$/i.test(String(id || ""))) {
    const e = new Error("Sesión inválida."); e.status = 400; throw e;
  }
  const snap = await db.ref(`sessions/${id}`).get();
  if (!snap.exists()) { const e = new Error("Sesión no encontrada."); e.status = 404; throw e; }
  const s = snap.val();
  if (Number(s.expiresAt) <= Date.now()) {
    await db.ref(`sessions/${id}`).remove();
    const e = new Error("La sesión expiró."); e.status = 410; throw e;
  }
  return s;
}

function publicSession(s) {
  return { id: s.id, dur: Number(s.dur), link: Number(s.link), state: s.state, createdAt: Number(s.createdAt), expiresAt: Number(s.expiresAt), returnToken: s.returnToken };
}

function sameDevice(s, deviceId) {
  return !deviceId || s.deviceId === deviceId;
}

module.exports = async (req, res) => {
  try {
    // CORS: permits the same deployed site and local file testing (Origin: null).
    // No credentials/cookies are used by this API.
    const origin = String(req.headers?.origin || "");
    if (origin === "https://keyzsystem.vercel.app" || origin === "null") {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Vary", "Origin");
    }
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Accept");
    if (String(req.method || "GET").toUpperCase() === "OPTIONS") {
      res.status(204).end();
      return;
    }
    const method = String(req.method || "GET").toUpperCase();
    const route = getRoute(req);

    if (method === "GET" && route === "health") {
      return json(res, 200, { ok: true, service: "znexus-api", version: "2026.1" });
    }

    if (!rateLimit(req, route || "root", route === "linkvertise/verify" ? 12 : 40)) {
      return json(res, 429, { error: "Demasiadas solicitudes. Espera un momento." });
    }

    const app = getAdmin();
    const db = app.database();
    const data = await readBody(req);

    if (method === "POST" && route === "session/start") {
      const hours = Number(data.hours);
      const deviceId = String(data.deviceId || "");
      if (!REQUIREMENTS[hours]) return json(res, 400, { error: "Duración inválida." });
      if (!validDeviceId(deviceId)) return json(res, 400, { error: "Device ID inválido." });

      const now = Date.now();
      const id = crypto.randomUUID();
      const returnToken = crypto.randomBytes(24).toString("hex");
      const session = { id, dur: hours, link: 1, state: "ready", createdAt: now, expiresAt: now + SESSION_TTL, deviceId, completedLinks: 0, attempts: 0, returnToken };
      await db.ref(`sessions/${id}`).set(session);
      return json(res, 200, { session: publicSession(session) });
    }

    if (method === "GET" && route === "session/get") {
      const q = getQuery(req);
      const session = await getSession(db, q.get("sessionId"));
      const deviceId = String(q.get("deviceId") || "");
      if (!sameDevice(session, deviceId)) return json(res, 403, { error: "El dispositivo no coincide con la sesión." });
      return json(res, 200, { session: publicSession(session) });
    }

    if (method === "POST" && route === "session/prepare-link") {
      const session = await getSession(db, data.sessionId);
      const link = Number(data.link);
      if (!sameDevice(session, String(data.deviceId || ""))) return json(res, 403, { error: "El dispositivo no coincide con la sesión." });
      if (session.state !== "ready" || link !== Number(session.link)) return json(res, 409, { error: "El enlace no está autorizado en este estado." });

      const target = new URL(`${PUBLIC_BASE_URL}/`);
      target.searchParams.set("session", session.id);
      target.searchParams.set("link", String(link));
      target.searchParams.set("returnToken", String(session.returnToken || ""));
      const redirectUrl = `${AD_PROVIDER_BASE_URL}?target=${encodeURIComponent(target.toString())}`;
      const startedAt = Date.now();
      await db.ref(`sessions/${session.id}`).update({ state: "awaiting_external_return", externalStartedAt: startedAt, attempts: Number(session.attempts || 0) + 1 });
      session.state = "awaiting_external_return";
      return json(res, 200, { session: publicSession(session), redirectUrl });
    }

    if (method === "POST" && route === "session/return") {
      const session = await getSession(db, data.sessionId);
      const deviceId = String(data.deviceId || "");
      const token = String(data.returnToken || "");
      const link = Number(data.link);
      if (!sameDevice(session, deviceId)) return json(res, 403, { error: "El dispositivo no coincide con la sesión." });
      if (!token || token !== String(session.returnToken || "")) return json(res, 400, { error: "Retorno de sesión inválido." });
      if (session.state !== "awaiting_external_return" || link !== Number(session.link)) return json(res, 409, { error: "Ese paso no está pendiente." });
      if (Date.now() - Number(session.externalStartedAt || 0) > SESSION_TTL) return json(res, 410, { error: "El tiempo del paso expiró." });

      const lockRef = db.ref(`sessions/${session.id}`);
      const tx = await lockRef.transaction(current => {
        if (!current || current.state !== "awaiting_external_return" || Number(current.link) !== link || String(current.returnToken || "") !== token) return;
        return { ...current, state: "verifying_return", returnUsedAt: Date.now() };
      });
      if (!tx.committed) return json(res, 409, { error: "Este retorno ya fue procesado." });

      const total = REQUIREMENTS[Number(session.dur)];
      const next = Number(session.link) < total ? Number(session.link) + 1 : Number(session.link);
      const completed = Math.min(total, Number(session.completedLinks || 0) + 1);
      const state = completed >= total ? "complete" : "ready";
      await lockRef.update({ link: next, completedLinks: completed, state, lastReturnedAt: Date.now(), returnToken: crypto.randomBytes(24).toString("hex") });
      const updated = { ...session, link: next, completedLinks: completed, state };
      return json(res, 200, { session: publicSession(updated), compatibility: true });
    }

    if (method === "POST" && route === "linkvertise/verify") {
      const session = await getSession(db, data.sessionId);
      const hash = String(data.hash || "").trim();
      const link = Number(data.link);
      if (!sameDevice(session, String(data.deviceId || ""))) return json(res, 403, { error: "El dispositivo no coincide con la sesión." });
      if (!/^[a-f0-9]{64}$/i.test(hash)) return json(res, 400, { error: "Comprobante inválido." });
      if (session.state !== "awaiting_external_return" || link !== Number(session.link)) return json(res, 409, { error: "Ese paso no está pendiente." });
      if (Date.now() - Number(session.externalStartedAt || 0) > SESSION_TTL) return json(res, 410, { error: "El tiempo del paso expiró." });

      // Lock the session before calling Linkvertise to prevent concurrent replay attempts.
      const lockRef = db.ref(`sessions/${session.id}`);
      const tx = await lockRef.transaction(current => {
        if (!current || current.state !== "awaiting_external_return" || Number(current.link) !== link) return;
        return { ...current, state: "verifying", verifyStartedAt: Date.now() };
      });
      if (!tx.committed) return json(res, 409, { error: "Este paso ya está siendo verificado." });

      const token = process.env.LINKVERTISE_ANTI_BYPASS_TOKEN;
      if (!token) {
        await lockRef.update({ state: "awaiting_external_return" });
        return json(res, 500, { error: "Falta la configuración de Linkvertise en el servidor." });
      }

      try {
        const verifyUrl = new URL("https://publisher.linkvertise.com/api/v1/anti_bypassing");
        verifyUrl.searchParams.set("token", token);
        verifyUrl.searchParams.set("hash", hash);
        const lv = await fetch(verifyUrl, { method: "POST", headers: { Accept: "text/plain" } });
        const result = (await lv.text()).trim();
        if (!lv.ok || result !== "TRUE") {
          await lockRef.update({ state: "awaiting_external_return", lastVerifyFailedAt: Date.now() });
          return json(res, 403, { error: "Linkvertise no confirmó este paso. El comprobante puede haber expirado o ya haber sido usado." });
        }

        const total = REQUIREMENTS[Number(session.dur)];
        const next = Number(session.link) < total ? Number(session.link) + 1 : Number(session.link);
        const completed = Math.min(total, Number(session.completedLinks || 0) + 1);
        const state = completed >= total ? "complete" : "ready";
        await lockRef.update({ link: next, completedLinks: completed, state, lastVerifiedAt: Date.now(), verifyStartedAt: null });
        const updated = { ...session, link: next, completedLinks: completed, state };
        return json(res, 200, { session: publicSession(updated) });
      } catch (e) {
        await lockRef.update({ state: "awaiting_external_return", lastVerifyErrorAt: Date.now() });
        throw e;
      }
    }

    if (method === "POST" && route === "key/generate") {
      const session = await getSession(db, data.sessionId);
      const deviceId = String(data.deviceId || "");
      const total = REQUIREMENTS[Number(session.dur)];
      if (!sameDevice(session, deviceId)) return json(res, 403, { error: "El dispositivo no coincide con la sesión." });
      if (session.state !== "complete" || Number(session.completedLinks) !== total) return json(res, 409, { error: "La sesión no completó todos los pasos." });

      // Idempotency: if the session already recorded a generated key, return it instead of creating duplicates.
      if (session.generatedKey) {
        const existing = await db.ref(`keys/${session.generatedKey}`).get();
        if (existing.exists()) return json(res, 200, { key: session.generatedKey, expiresAt: Number(existing.val().expiresAt) });
      }

      const key = KEY_PREFIX + crypto.randomBytes(8).toString("hex").slice(0, 9).toUpperCase();
      const createdAt = Date.now();
      const expiresAt = createdAt + Number(session.dur) * 60 * 60 * 1000;
      await db.ref(`keys/${key}`).set({ createdAt, expiresAt, hwid: session.deviceId, hours_duration: Number(session.dur), sessionId: session.id, status: "active" });
      await db.ref(`sessions/${session.id}`).update({ state: "issued", generatedKey: key, generatedAt: createdAt });
      await db.ref(`sessions/${session.id}`).remove();
      return json(res, 200, { key, expiresAt });
    }

    if (method === "GET" && route === "key/validate") {
      const q = getQuery(req);
      const key = String(q.get("key") || "");
      const deviceId = String(q.get("deviceId") || "");
      if (!/^ZNEXUS-[A-Z0-9]{9}$/.test(key) || !validDeviceId(deviceId)) return json(res, 200, { valid: false });
      const snap = await db.ref(`keys/${key}`).get();
      if (!snap.exists()) return json(res, 200, { valid: false });
      const k = snap.val();
      const valid = k.status !== "revoked" && k.hwid === deviceId && Number(k.expiresAt) > Date.now();
      if (!valid) return json(res, 200, { valid: false });
      return json(res, 200, { valid: true, expiresAt: Number(k.expiresAt) });
    }

    return json(res, 404, { error: "Ruta API no encontrada." });
  } catch (err) {
    console.error(err);
    return json(res, Number(err.status) || 500, { error: err.message || "Error interno del servidor." });
  }
};
