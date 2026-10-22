// ============================================================
//  ALTAS DE OBRA - servidor (Cloudflare Worker)
//  - Sirve la app (archivos estáticos) y la API en /api/*
//  - Candado: Cloudflare Access. Aquí se verifica el token de Access
//    y luego que el correo esté dado de alta en la tabla "usuarios".
//  - Consulta de constancia del SAT por QR (/api/sat)
// ============================================================

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS usuarios(email TEXT PRIMARY KEY, nombre TEXT NOT NULL DEFAULT '', rol TEXT NOT NULL DEFAULT 'supervisor', activo INTEGER NOT NULL DEFAULT 1, creado TEXT)`,
  `CREATE TABLE IF NOT EXISTS obras(nombre TEXT PRIMARY KEY, creado TEXT)`,
  `CREATE TABLE IF NOT EXISTS usuario_obras(email TEXT NOT NULL, obra TEXT NOT NULL, PRIMARY KEY(email, obra))`,
  `CREATE TABLE IF NOT EXISTS bitacora(id INTEGER PRIMARY KEY AUTOINCREMENT, fecha TEXT NOT NULL, email TEXT NOT NULL, accion TEXT NOT NULL, detalle TEXT)`,
];
let schemaListo = false;
async function asegurarTablas(env) {
  if (schemaListo) return;
  await env.DB.batch(SCHEMA.map(s => env.DB.prepare(s)));
  schemaListo = true;
}

const ahora = () => new Date().toISOString();
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });
class ErrorHttp extends Error { constructor(status, msg) { super(msg); this.status = status; } }

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(req);
    try {
      await asegurarTablas(env);
      const yo = await usuarioActual(req, env);
      return await api(req, env, url, yo);
    } catch (e) {
      if (e instanceof ErrorHttp) return json({ ok: false, error: e.message }, e.status);
      return json({ ok: false, error: "Error del servidor: " + (e.message || e) }, 500);
    }
  },
};

// ---------------- quién es ----------------
async function usuarioActual(req, env) {
  let email = "";
  const host = new URL(req.url).hostname;
  if (env.DEV_EMAIL && (host === "localhost" || host === "127.0.0.1")) email = env.DEV_EMAIL; // solo pruebas locales
  else email = await emailDeAccess(req, env);
  email = email.trim().toLowerCase();

  const admins = (env.ADMIN_EMAILS || "").toLowerCase().split(",").map(s => s.trim()).filter(Boolean);
  if (admins.includes(email)) {
    await env.DB.prepare(`INSERT INTO usuarios(email, nombre, rol, activo, creado) VALUES(?, '', 'admin', 1, ?)
      ON CONFLICT(email) DO UPDATE SET rol='admin', activo=1`).bind(email, ahora()).run();
  }
  const u = await env.DB.prepare(`SELECT email, nombre, rol, activo FROM usuarios WHERE email=?`).bind(email).first();
  if (!u || !u.activo) throw new ErrorHttp(403, `El correo ${email} no tiene acceso. Pide al administrador que te dé de alta.`);
  let obras;
  if (u.rol === "admin") obras = (await env.DB.prepare(`SELECT nombre FROM obras ORDER BY nombre`).all()).results.map(r => r.nombre);
  else obras = (await env.DB.prepare(`SELECT obra FROM usuario_obras WHERE email=? ORDER BY obra`).bind(email).all()).results.map(r => r.obra);
  return { email: u.email, nombre: u.nombre, rol: u.rol, obras };
}

let CERTS = null, CERTS_T = 0;
async function emailDeAccess(req, env) {
  const team = (env.ACCESS_TEAM_DOMAIN || "").replace(/\/+$/, "");
  const aud = env.ACCESS_AUD || "";
  if (!team || !aud) throw new ErrorHttp(503, "El candado (Cloudflare Access) todavía no está configurado.");
  let token = req.headers.get("Cf-Access-Jwt-Assertion");
  if (!token) { const m = (req.headers.get("Cookie") || "").match(/(?:^|;\s*)CF_Authorization=([^;]+)/); token = m && m[1]; }
  if (!token) throw new ErrorHttp(401, "Sesión vencida. Recarga la página para volver a entrar.");
  const [h64, p64, s64] = token.split(".");
  if (!s64) throw new ErrorHttp(401, "Sesión no válida.");
  const head = JSON.parse(b64txt(h64)), pay = JSON.parse(b64txt(p64));
  if (!CERTS || Date.now() - CERTS_T > 3600e3 || !CERTS.find(k => k.kid === head.kid)) {
    CERTS = (await (await fetch(team + "/cdn-cgi/access/certs")).json()).keys; CERTS_T = Date.now();
  }
  const jwk = CERTS.find(k => k.kid === head.kid);
  if (!jwk) throw new ErrorHttp(401, "Sesión no válida.");
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64bytes(s64), new TextEncoder().encode(h64 + "." + p64));
  const auds = Array.isArray(pay.aud) ? pay.aud : [pay.aud];
  if (!ok || !auds.includes(aud) || pay.iss !== team || !(pay.exp * 1000 > Date.now()) || !pay.email)
    throw new ErrorHttp(401, "Sesión vencida. Recarga la página para volver a entrar.");
  return pay.email;
}
function b64bytes(s) { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }
function b64txt(s) { return new TextDecoder().decode(b64bytes(s)); }

// ---------------- rutas ----------------
async function api(req, env, url, yo) {
  const r = url.pathname;
  if (r === "/api/yo" && req.method === "GET") return json({ ok: true, ...yo });
  if (r === "/api/sat" && req.method === "GET") return await consultaSat(url);

  if (r.startsWith("/api/admin/")) {
    if (yo.rol !== "admin") throw new ErrorHttp(403, "Solo el administrador puede hacer esto.");
    const body = req.method === "POST" ? await req.json().catch(() => ({})) : {};
    const log = (accion, detalle) => env.DB.prepare(`INSERT INTO bitacora(fecha, email, accion, detalle) VALUES(?,?,?,?)`).bind(ahora(), yo.email, accion, JSON.stringify(detalle)).run();

    if (r === "/api/admin/datos" && req.method === "GET") {
      const us = (await env.DB.prepare(`SELECT email, nombre, rol, activo FROM usuarios ORDER BY rol, email`).all()).results;
      const uo = (await env.DB.prepare(`SELECT email, obra FROM usuario_obras`).all()).results;
      const obras = (await env.DB.prepare(`SELECT nombre FROM obras ORDER BY nombre`).all()).results.map(o => o.nombre);
      for (const u of us) u.obras = uo.filter(x => x.email === u.email).map(x => x.obra);
      return json({ ok: true, usuarios: us, obras });
    }
    if (r === "/api/admin/obra" && req.method === "POST") {
      const nombre = limpiarObra(body.nombre);
      if (!nombre) throw new ErrorHttp(400, "Escribe el nombre de la obra.");
      await env.DB.prepare(`INSERT OR IGNORE INTO obras(nombre, creado) VALUES(?, ?)`).bind(nombre, ahora()).run();
      await log("alta obra", { nombre });
      return json({ ok: true });
    }
    if (r === "/api/admin/borrar-obra" && req.method === "POST") {
      const nombre = limpiarObra(body.nombre);
      await env.DB.batch([
        env.DB.prepare(`DELETE FROM usuario_obras WHERE obra=?`).bind(nombre),
        env.DB.prepare(`DELETE FROM obras WHERE nombre=?`).bind(nombre),
      ]);
      await log("baja obra", { nombre });
      return json({ ok: true });
    }
    if (r === "/api/admin/usuario" && req.method === "POST") {
      const email = String(body.email || "").trim().toLowerCase();
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw new ErrorHttp(400, "Correo no válido.");
      const rol = body.rol === "admin" ? "admin" : "supervisor";
      const activo = body.activo === false ? 0 : 1;
      if (email === yo.email && (rol !== "admin" || !activo)) throw new ErrorHttp(400, "No puedes quitarte a ti mismo el acceso de administrador.");
      const obras = [...new Set((body.obras || []).map(limpiarObra).filter(Boolean))];
      const existentes = (await env.DB.prepare(`SELECT nombre FROM obras`).all()).results.map(o => o.nombre);
      const malas = obras.filter(o => !existentes.includes(o));
      if (malas.length) throw new ErrorHttp(400, "Estas obras no existen: " + malas.join(", "));
      await env.DB.batch([
        env.DB.prepare(`INSERT INTO usuarios(email, nombre, rol, activo, creado) VALUES(?,?,?,?,?)
          ON CONFLICT(email) DO UPDATE SET nombre=excluded.nombre, rol=excluded.rol, activo=excluded.activo`).bind(email, String(body.nombre || "").trim().toUpperCase(), rol, activo, ahora()),
        env.DB.prepare(`DELETE FROM usuario_obras WHERE email=?`).bind(email),
        ...obras.map(o => env.DB.prepare(`INSERT INTO usuario_obras(email, obra) VALUES(?,?)`).bind(email, o)),
      ]);
      await log("guardar usuario", { email, rol, activo, obras });
      return json({ ok: true });
    }
    if (r === "/api/admin/borrar-usuario" && req.method === "POST") {
      const email = String(body.email || "").trim().toLowerCase();
      if (email === yo.email) throw new ErrorHttp(400, "No puedes borrarte a ti mismo.");
      await env.DB.batch([
        env.DB.prepare(`DELETE FROM usuario_obras WHERE email=?`).bind(email),
        env.DB.prepare(`DELETE FROM usuarios WHERE email=?`).bind(email),
      ]);
      await log("borrar usuario", { email });
      return json({ ok: true });
    }
  }
  throw new ErrorHttp(404, "Ruta no encontrada.");
}
const limpiarObra = s => String(s || "").normalize("NFC").trim().replace(/\s+/g, " ").toUpperCase().slice(0, 80);

// ---------------- SAT ----------------
async function consultaSat(url) {
  const qr = url.searchParams.get("qr") || "";
  let u;
  try { u = new URL(qr); } catch { return json({ ok: false, error: "Link de QR no válido" }, 400); }
  if (u.protocol !== "https:" || u.hostname !== "siat.sat.gob.mx" || !u.pathname.startsWith("/app/qr/"))
    return json({ ok: false, error: "Solo se aceptan links del SAT" }, 400);
  let html;
  try {
    const r = await fetch(u.toString(), { headers: {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130 Safari/537.36",
      "Accept": "text/html", "Accept-Language": "es-MX,es;q=0.9" } });
    if (!r.ok) return json({ ok: false, error: "El SAT respondió " + r.status }, 502);
    html = await r.text();
  } catch (e) { return json({ ok: false, error: "No se pudo conectar al SAT" }, 502); }
  const d = extraerSat(aLineas(html));
  if (!d.rfc && !d.curp) return json({ ok: false, error: "La página del SAT no trajo datos" }, 422);
  return json({ ok: true, ...d });
}
const ENT = { nbsp: " ", amp: "&", quot: '"', lt: "<", gt: ">", aacute: "á", eacute: "é", iacute: "í", oacute: "ó", uacute: "ú",
  Aacute: "Á", Eacute: "É", Iacute: "Í", Oacute: "Ó", Uacute: "Ú", ntilde: "ñ", Ntilde: "Ñ", uuml: "ü", Uuml: "Ü" };
function aLineas(html) {
  return html.replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>/gi, "").replace(/<[^>]+>/g, "\n")
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n)).replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCharCode(parseInt(n, 16)))
    .replace(/&([a-z]+);/gi, (m, n) => ENT[n] ?? m)
    .split("\n").map(s => s.replace(/\s+/g, " ").trim()).filter(Boolean);
}
const sinAcentos = s => s.normalize("NFD").replace(/[̀-ͯ]/g, "").toUpperCase().replace(/\s+/g, " ").trim();
function extraerSat(L) {
  const N = L.map(sinAcentos);
  const dato = etq => {
    const e = sinAcentos(etq);
    for (let k = 0; k < N.length; k++) {
      if (N[k] === e + ":" || N[k] === e) { const sig = L[k + 1] || ""; return sig.endsWith(":") ? "" : sig; }
      if (N[k].startsWith(e + ":")) return L[k].slice(L[k].indexOf(":") + 1).trim();
    }
    return "";
  };
  const rfcM = L.join(" ").match(/RFC:?\s*([A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3})/i);
  return {
    rfc: rfcM ? rfcM[1].toUpperCase() : "", curp: dato("CURP"), nombre: dato("Nombre"),
    paterno: dato("Apellido Paterno"), materno: dato("Apellido Materno"), situacion: dato("Situación del contribuyente"),
    estado: dato("Entidad Federativa"), municipio: dato("Municipio o delegación"), colonia: dato("Colonia"),
    cp: dato("CP"), regimen: dato("Régimen"),
  };
}
