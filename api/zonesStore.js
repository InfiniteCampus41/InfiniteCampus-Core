import fs from "fs";
import path from "path";
const DEFAULT_ZONE_URLS = [
    "",
    "",
    ""
];
const DEFAULT_COVER_BASE = "";
const DEFAULT_GAME_HOST = "";
const DEFAULT_GAME_BASE = "";
let warnedMissingEnv = false;
function getZoneUrls() {
    const fromEnv = [process.env.ZONE1, process.env.ZONE2, process.env.ZONE3].filter(Boolean);
    if (fromEnv.length) return fromEnv;
    if (!warnedMissingEnv) {
        console.warn("zoneStore: ZONE1/ZONE2/ZONE3 not set in env, falling back to built-in defaults");
        warnedMissingEnv = true;
    }
    return DEFAULT_ZONE_URLS;
}
function getCoverBase() {
    return process.env.COVER_BASE || DEFAULT_COVER_BASE;
}
function getGameHost() {
    const envHost = process.env.GAME_HOST;
    if (!envHost) return DEFAULT_GAME_HOST;
    if (envHost.includes("://")) {
        try {
            return new URL(envHost).hostname;
        } catch {
            log("getGameHost: GAME_HOST env var looks like a URL but failed to parse:", envHost);
            return DEFAULT_GAME_HOST;
        }
    }
    return envHost;
}
function getGameBase() {
    return process.env.GAME_BASE || DEFAULT_GAME_BASE;
}
const ZONE_CACHE_TTL_MS = 10 * 60 * 1000;
const FETCH_TIMEOUT_MS = 15000;
const ZONE_KEY_PREFIX = "zone:";
const CUSTOM_GAME_CSS = `
    html, body {
        margin: 0;
        padding: 0;
        width: 100%;
        height: 100%;
        background: #0b0b0f;
        overflow: hidden;
    }
    #content, #content canvas {
        max-height: 100% !important;
    }
    .zone-header {
        display:none;
    }
`;
let zoneCache = { data: null, fetchedAt: 0 };
let inFlightFetch = null;
let zoneRefreshTimer = null;
function isValidZoneGame(z) {
    return (
        z &&
        typeof z === "object" &&
        typeof z.id === "number" &&
        Number.isFinite(z.id) &&
        z.id >= 0 &&
        typeof z.name === "string" &&
        z.name.trim().length > 0 &&
        typeof z.author === "string" &&
        z.author.trim().length > 0
    );
}
async function fetchWithTimeout(url, opts = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
        return await fetch(url, { ...opts, signal: controller.signal });
    } finally {
        clearTimeout(timeout);
    }
}
async function fetchWithRetry(url, opts = {}, retries = 1) {
    let lastErr;
    for (let attempt = 0; attempt <= retries; attempt++) {
        try {
            return await fetchWithTimeout(url, opts);
        } catch (e) {
            lastErr = e;
            if (attempt < retries) {
                log("fetchWithRetry: attempt", attempt + 1, "failed for", url, "-", e.message, "- retrying");
                await new Promise((r) => setTimeout(r, 500));
            }
        }
    }
    throw lastErr;
}
async function fetchZonesFresh() {
    let lastErr = null;
    for (const url of getZoneUrls()) {
        log("fetching zones from", url);
        try {
            const res = await fetchWithTimeout(url, {
                headers: { "User-Agent": "Mozilla/5.0 (compatible; InfiniteCampusZoneFetch/1.0)" },
            });
            log("zones response from", url, "status", res.status);
            if (!res.ok) throw new Error(`Bad Status ${res.status}`);
            const json = await res.json();
            if (!Array.isArray(json)) throw new Error("Invalid Zones Format");
            log("zones fetch OK from", url, "entries:", json.length);
            return json;
        } catch (e) {
            log("zones fetch FAILED from", url, "-", e.message);
            lastErr = e;
        }
    }
    throw lastErr || new Error("Failed To Fetch Zones");
}
async function getZones() {
    if (zoneCache.data) {
        log("getZones: serving in-memory zones, entries:", zoneCache.data.length, "age(ms):", Date.now() - zoneCache.fetchedAt);
        return zoneCache.data;
    }
    log("getZones: no zones in memory - attempting on-demand fetch");
    if (!inFlightFetch) {
        inFlightFetch = fetchZonesFresh()
            .then((data) => {
                zoneCache = { data, fetchedAt: Date.now() };
                return data;
            })
            .finally(() => { inFlightFetch = null; });
    }
    try {
        return await inFlightFetch;
    } catch (e) {
        errlog("getZones: on-demand fetch also failed -", e.message);
        throw new Error("Zones Not Loaded");
    }
}
async function refreshZonesFromNetwork() {
    log("refreshZonesFromNetwork: forcing a fresh fetch from the zones feed");
    const data = await fetchZonesFresh();
    zoneCache = { data, fetchedAt: Date.now() };
    return data;
}
function startZoneRefreshLoop() {
    if (zoneRefreshTimer) return;
    zoneRefreshTimer = setInterval(async () => {
        try {
            await refreshZonesFromNetwork();
            log("background refresh: zones updated, entries:", zoneCache.data.length);
        } catch (e) {
            errlog("background refresh: FAILED, continuing to serve stale/cached zones -", e.message);
        }
    }, ZONE_CACHE_TTL_MS);
    if (zoneRefreshTimer.unref) zoneRefreshTimer.unref();
}
function shuffle(arr) {
    const out = arr.slice();
    for (let i = out.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [out[i], out[j]] = [out[j], out[i]];
    }
    return out;
}
function zoneKey(id) {
    return `${ZONE_KEY_PREFIX}${id}`;
}
function injectHead(html, extra) {
    if (/<\/head>/i.test(html)) return html.replace(/<\/head>/i, `${extra}</head>`);
    const headOpenMatch = html.match(/<head[^>]*>/i);
    if (headOpenMatch) {
        const idx = headOpenMatch.index + headOpenMatch[0].length;
        return html.slice(0, idx) + extra + html.slice(idx);
    }
    const htmlOpenMatch = html.match(/<html[^>]*>/i);
    if (htmlOpenMatch) {
        const idx = htmlOpenMatch.index + htmlOpenMatch[0].length;
        return html.slice(0, idx) + `<head>${extra}</head>` + html.slice(idx);
    }
    return extra + html;
}
function injectBaseTag(html, baseHref) {
    if (/<base(?=[\s/>])/i.test(html)) return html;
    return injectHead(html, `<base href="${baseHref}">`);
}
function log(...args) {
    console.log("[zoneStore]", ...args);
}
function errlog(...args) {
    console.error("[zoneStore]", ...args);
}
function injectCustomCss(html) {
    return injectHead(html, `
        <style id="ic-zone-game-style">
        ${CUSTOM_GAME_CSS}
        </style>
        <script>
        (() => {
            function applyMaxHeight() {
                try {
                    const content = document.getElementById("content");
                    if (content) {
                        content.style.maxHeight = "100%";
                        return true;
                    }
                    const zoneFrame = document.getElementById("zoneFrame");
                    if (zoneFrame && zoneFrame.contentDocument) {
                        const innerContent = zoneFrame.contentDocument.getElementById("content");
                        if (innerContent) {
                            innerContent.style.maxHeight = "100%";
                            return true;
                        }
                    }
                } catch (e) {}
                return false;
            }
            const timer = setInterval(() => {
                if (applyMaxHeight()) {
                    clearInterval(timer);
                }
            }, 100);
            window.addEventListener("load", applyMaxHeight);
            new MutationObserver(applyMaxHeight).observe(document.documentElement, {
                childList: true,
                subtree: true
            });
        })();
        </script>
    `);
}
function ensureGamesFile(GAMES_JSON) {
    if (!fs.existsSync(GAMES_JSON)) fs.writeFileSync(GAMES_JSON, JSON.stringify({}, null, 2));
}
function loadGamesJSON(GAMES_JSON) {
    try {
        return JSON.parse(fs.readFileSync(GAMES_JSON, "utf8"));
    } catch {
        return {};
    }
}
function saveGamesJSON(GAMES_JSON, games) {
    const nonZone = {};
    const zoneEntries = [];
    for (const [key, val] of Object.entries(games)) {
        if (key.startsWith(ZONE_KEY_PREFIX)) {
            const idNum = Number(key.slice(ZONE_KEY_PREFIX.length));
            zoneEntries.push([key, val, Number.isFinite(idNum) ? idNum : Infinity]);
        } else {
            nonZone[key] = val;
        }
    }
    zoneEntries.sort((a, b) => a[2] - b[2]);
    const merged = { ...nonZone };
    for (const [key, val] of zoneEntries) merged[key] = val;
    fs.writeFileSync(GAMES_JSON, JSON.stringify(merged, null, 2));
}
function getHiddenIdSet(games) {
    const hidden = Array.isArray(games._hidden) ? games._hidden : [];
    return new Set(hidden.map(String));
}
function buildListFromZones(zones, games) {
    const valid = zones.filter(isValidZoneGame);
    return valid.map((z) => {
        const key = zoneKey(z.id);
        if (!games[key]) {
            games[key] = { popularity: 0, dateAdded: Date.now() };
        }
        const stored = games[key];
        return {
            id: z.id,
            name: z.name,
            author: z.author || null,
            authorLink: typeof z.authorLink === "string" && z.authorLink ? z.authorLink : null,
            hasThumbnail: true,
            popularity: stored.popularity || 0,
            dateAdded: stored.dateAdded || null,
        };
    });
}
async function mergeZonesIntoGamesJSON(GAMES_JSON) {
    const zones = await refreshZonesFromNetwork();
    const games = loadGamesJSON(GAMES_JSON);
    const list = buildListFromZones(zones, games);
    games._list = list;
    saveGamesJSON(GAMES_JSON, games);
    log("mergeZonesIntoGamesJSON: merged", list.length, "zone games into games.json");
    return list;
}
export async function initZoneGames(deps) {
    const { __dirname } = deps;
    const GAMES_JSON = path.join(__dirname, "games.json");
    ensureGamesFile(GAMES_JSON);
    try {
        await mergeZonesIntoGamesJSON(GAMES_JSON);
        log("initZoneGames: startup zone fetch + merge succeeded");
    } catch (e) {
        errlog("initZoneGames: startup zone fetch FAILED -", e.message, "- serving existing games.json (if any) with no live zone validation until the next refresh succeeds");
    }
    startZoneRefreshLoop();
}
function isAdminPass(req) {
    const pass = req.headers["x-admin-password"];
    return pass === process.env.ADMIN_PASSWORD || pass === process.env.ADMIN_PASSWORD_2;
}
export function attachZoneGameRoutes(app, deps) {
    const { __dirname } = deps;
    const GAMES_JSON = path.join(__dirname, "games.json");
    ensureGamesFile(GAMES_JSON);
    app.get("/api/zone-games", async (req, res) => {
        log("GET /api/zone-games from", req.ip);
        res.setHeader("Cache-Control", "public, max-age=60, stale-while-revalidate=300");
        try {
            const games = loadGamesJSON(GAMES_JSON);
            const hidden = getHiddenIdSet(games);
            const list = Array.isArray(games._list) ? games._list.filter((g) => !hidden.has(String(g.id))) : [];
            log("zone-games: serving list from games.json -", list.length, "games (", hidden.size, "hidden)");
            res.json({ ok: true, games: shuffle(list) });
        } catch (e) {
            console.error("Zone Games List Error:", e.message);
            errlog("zone-games: FAILED -", e.stack || e.message);
            res.status(502).json({ ok: false, error: "Failed To Load Games" });
        }
    });
    app.post("/admin/zone-games/regenerate", async (req, res) => {
        if (!isAdminPass(req)) {
            return res.status(403).json({ ok: false, error: "Not Allowed" });
        }
        try {
            const list = await mergeZonesIntoGamesJSON(GAMES_JSON);
            log("zone-games: /admin/zone-games/regenerate forced a fresh zones fetch, entries:", list.length);
            res.json({ ok: true, count: list.length });
        } catch (e) {
            errlog("zone-games: regenerate FAILED -", e.stack || e.message);
            res.status(500).json({ ok: false, error: "Failed To Refresh Zones" });
        }
    });
    app.get("/admin/games-json", (req, res) => {
        if (!isAdminPass(req)) {
            return res.status(403).json({ ok: false, error: "Not Allowed" });
        }
        try {
            res.json({ ok: true, games: loadGamesJSON(GAMES_JSON) });
        } catch (e) {
            errlog("games-json: GET FAILED -", e.stack || e.message);
            res.status(500).json({ ok: false, error: "Failed To Load games.json" });
        }
    });
    app.post("/admin/games-json", (req, res) => {
        if (!isAdminPass(req)) {
            return res.status(403).json({ ok: false, error: "Not Allowed" });
        }
        try {
            const { games } = req.body || {};
            if (!games || typeof games !== "object" || Array.isArray(games)) {
                return res.status(400).json({ ok: false, error: "Invalid games.json Payload" });
            }
            saveGamesJSON(GAMES_JSON, games);
            log("games-json: saved via admin edit -", Object.keys(games).length, "top-level keys");
            res.json({ ok: true });
        } catch (e) {
            errlog("games-json: POST FAILED -", e.stack || e.message);
            res.status(500).json({ ok: false, error: "Failed To Save games.json" });
        }
    });
    app.get("/admin/hidden-games", (req, res) => {
        if (!isAdminPass(req)) {
            return res.status(403).json({ ok: false, error: "Not Allowed" });
        }
        try {
            const games = loadGamesJSON(GAMES_JSON);
            const hidden = Array.isArray(games._hidden) ? games._hidden.map(String) : [];
            res.json({ ok: true, hidden });
        } catch (e) {
            errlog("hidden-games: GET FAILED -", e.stack || e.message);
            res.status(500).json({ ok: false, error: "Failed To Load Hidden Games" });
        }
    });
    app.post("/admin/hidden-games", (req, res) => {
        if (!isAdminPass(req)) {
            return res.status(403).json({ ok: false, error: "Not Allowed" });
        }
        try {
            const { hidden } = req.body || {};
            if (!Array.isArray(hidden)) {
                return res.status(400).json({ ok: false, error: "Invalid Hidden List" });
            }
            const games = loadGamesJSON(GAMES_JSON);
            games._hidden = hidden.map(String).filter(Boolean);
            saveGamesJSON(GAMES_JSON, games);
            log("hidden-games: saved -", games._hidden.length, "hidden id(s)");
            res.json({ ok: true, hidden: games._hidden });
        } catch (e) {
            errlog("hidden-games: POST FAILED -", e.stack || e.message);
            res.status(500).json({ ok: false, error: "Failed To Save Hidden Games" });
        }
    });
    const popularityDebounce = new Map();
    app.post("/api/zone-games/:id/popularity", async (req, res) => {
        const id = req.params.id;
        log("POST /api/zone-games/" + id + "/popularity from", req.ip);
        try {
            if (!/^\d+$/.test(id)) {
                log("popularity: rejected, invalid id", id);
                return res.status(400).json({ ok: false, error: "Invalid Id" });
            }
            const zones = await getZones();
            const z = zones.find((z) => String(z.id) === id && isValidZoneGame(z));
            if (!z) {
                log("popularity: id", id, "not found in zones feed");
                return res.status(404).json({ ok: false, error: "Not Found" });
            }
            const games = loadGamesJSON(GAMES_JSON);
            const key = zoneKey(id);
            if (!games[key]) games[key] = { popularity: 0, dateAdded: Date.now() };
            const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket?.remoteAddress || "unknown";
            const dkey = `${ip}:${id}`;
            const now = Date.now();
            const last = popularityDebounce.get(dkey) || 0;
            if (now - last > 10_000) {
                games[key].popularity = (games[key].popularity || 0) + 1;
                popularityDebounce.set(dkey, now);
                if (Array.isArray(games._list)) {
                    const entry = games._list.find((g) => String(g.id) === id);
                    if (entry) entry.popularity = games[key].popularity;
                }
                saveGamesJSON(GAMES_JSON, games);
                log("popularity: bumped id", id, "to", games[key].popularity);
            } else {
                log("popularity: debounced for id", id, "(", ip, ")");
            }
            res.json({ ok: true, popularity: games[key].popularity });
        } catch (e) {
            errlog("popularity: FAILED for id", id, "-", e.stack || e.message);
            res.status(500).json({ ok: false });
        }
    });
    app.get("/zonegames/:id/thumbnail", async (req, res) => {
        const id = req.params.id;
        log("GET /zonegames/" + id + "/thumbnail from", req.ip);
        try {
            if (!/^\d+$/.test(id)) {
                log("thumbnail: rejected, invalid id", id);
                return res.status(400).send("Bad Request");
            }
            const zones = await getZones();
            const z = zones.find((z) => String(z.id) === id && isValidZoneGame(z));
            if (!z) {
                log("thumbnail: id", id, "not found in zones feed");
                return res.status(404).send("Not Found");
            }
            const thumbUrl = `${getCoverBase()}/${encodeURIComponent(id)}.png`;
            log("thumbnail: fetching upstream for id", id, "->", thumbUrl);
            let upstream;
            try {
                upstream = await fetchWithTimeout(thumbUrl, {
                    headers: { "User-Agent": "Mozilla/5.0 (compatible; InfiniteCampusThumbProxy/1.0)" },
                });
            } catch (e) {
                errlog("thumbnail: upstream fetch threw for id", id, "-", e.message);
                return res.status(502).send("Proxy Error");
            }
            log("thumbnail: upstream status for id", id, "=", upstream.status);
            if (!upstream.ok) return res.status(404).send("Not Found");
            const contentType = upstream.headers.get("content-type") || "image/png";
            res.setHeader("Content-Type", contentType.startsWith("image/") ? contentType : "image/png");
            res.setHeader("X-Content-Type-Options", "nosniff");
            res.setHeader("Cache-Control", "public, max-age=604800, stale-while-revalidate=2592000, immutable");
            const buf = Buffer.from(await upstream.arrayBuffer());
            log("thumbnail: served id", id, "-", buf.length, "bytes,", contentType);
            res.send(buf);
        } catch (e) {
            errlog("thumbnail: FAILED for id", id, "-", e.stack || e.message);
            if (!res.headersSent) res.status(502).send("Proxy Error");
        }
    });
    app.get("/games/:id{/*rest}", async (req, res) => {
        const id = req.params.id;
        const rest = Array.isArray(req.params.rest) ? req.params.rest.join("/") : req.params.rest || "";
        log("GET /games/" + id + (rest ? "/" + rest : ""), "from", req.ip, "referer:", req.headers.referer || "(none)");
        try {
            if (!/^\d+$/.test(id)) {
                log("games proxy: rejected, invalid id", id);
                return res.status(404).send("Not Found");
            }
            const zones = await getZones();
            const z = zones.find((z) => String(z.id) === id && isValidZoneGame(z));
            if (!z) {
                log("games proxy: id", id, "not found in zones feed");
                return res.status(404).send("Not Found");
            }
            const gameBase = getGameBase();
            let target;
            let fetchUrl;
            try {
                if (rest) {
                    target = new URL(rest, gameBase + "/");
                    fetchUrl = target.toString();
                } else {
                    fetchUrl = `${gameBase}?id=${encodeURIComponent(id)}`;
                    target = new URL(fetchUrl);
                }
            } catch (e) {
                log("games proxy: bad path for id", id, "rest:", rest, "-", e.message);
                return res.status(400).send("Bad Path");
            }
            log("games proxy: resolved target ->", fetchUrl, "(hostname:", target.hostname + ")");
            if (target.hostname !== getGameHost()) {
                log("games proxy: BLOCKED, hostname", target.hostname, "!=", getGameHost());
                return res.status(403).send("Blocked");
            }
            if (target.protocol !== "https:" && target.protocol !== "http:") {
                log("games proxy: bad protocol", target.protocol);
                return res.status(400).send("Bad Path");
            }
            let upstream;
            try {
                upstream = await fetchWithRetry(fetchUrl, {
                    redirect: "follow",
                    headers: { "User-Agent": "Mozilla/5.0 (compatible; InfiniteCampusGameProxy/1.0)" },
                });
            } catch (e) {
                errlog("games proxy: upstream fetch threw for", fetchUrl, "-", e.message);
                return res.status(502).send("Proxy Error");
            }
            log("games proxy: upstream", fetchUrl, "-> status", upstream.status, "final url:", upstream.url);
            if (!upstream.ok && upstream.status !== 304) {
                log("games proxy: upstream non-OK status", upstream.status, "for", fetchUrl);
                return res.status(upstream.status).send("Upstream Error");
            }
            const contentType = upstream.headers.get("content-type") || "application/octet-stream";
            log("games proxy: content-type", contentType, "for", fetchUrl);
            res.setHeader("X-Content-Type-Options", "nosniff");
            res.setHeader("Cache-Control", "public, max-age=300");
            if (contentType.includes("text/html")) {
                const html = await upstream.text();
                const basePath = `/games/${encodeURIComponent(id)}/`;
                res.setHeader("Content-Type", "text/html; charset=utf-8");
                log("games proxy: serving HTML for id", id, "-", html.length, "chars, basePath", basePath);
                return res.send(injectCustomCss(injectBaseTag(html, basePath)));
            }
            res.setHeader("Content-Type", contentType);
            const buf = Buffer.from(await upstream.arrayBuffer());
            log("games proxy: serving asset for id", id, "-", buf.length, "bytes,", contentType);
            res.send(buf);
        } catch (e) {
            console.error("Zone Game Proxy Error:", e.message);
            errlog("games proxy: FAILED for id", id, "-", e.stack || e.message);
            if (!res.headersSent) res.status(502).send("Proxy Error");
        }
    });
    app.get("/commits", async (req, res) => {
        log("GET /commits from", req.ip);
        try {
            const gameBase = getGameBase();
            const fetchUrl = `${gameBase}/commits`;
            let target;
            try {
                target = new URL(fetchUrl);
            } catch (e) {
                log("commits: bad url", fetchUrl, "-", e.message);
                return res.status(500).send("Bad Config");
            }
            if (target.hostname !== getGameHost()) {
                log("commits: BLOCKED, hostname", target.hostname, "!=", getGameHost());
                return res.status(403).send("Blocked");
            }
            if (target.protocol !== "https:" && target.protocol !== "http:") {
                log("commits: bad protocol", target.protocol);
                return res.status(400).send("Bad Path");
            }
            log("commits: fetching upstream ->", fetchUrl);
            let upstream;
            try {
                upstream = await fetchWithTimeout(fetchUrl, {
                    redirect: "follow",
                    headers: { "User-Agent": "Mozilla/5.0 (compatible; InfiniteCampusGameProxy/1.0)" },
                });
            } catch (e) {
                errlog("commits: upstream fetch threw -", e.message);
                return res.status(502).send("Proxy Error");
            }
            log("commits: upstream status", upstream.status, "final url:", upstream.url);
            if (!upstream.ok && upstream.status !== 304) {
                return res.status(upstream.status).send("Upstream Error");
            }
            const contentType = upstream.headers.get("content-type") || "application/octet-stream";
            res.setHeader("X-Content-Type-Options", "nosniff");
            res.setHeader("Cache-Control", "public, max-age=60");
            if (contentType.includes("application/json")) {
                const json = await upstream.text();
                res.setHeader("Content-Type", "application/json; charset=utf-8");
                log("commits: serving JSON -", json.length, "chars");
                return res.send(json);
            }
            if (contentType.includes("text/html")) {
                const html = await upstream.text();
                res.setHeader("Content-Type", "text/html; charset=utf-8");
                log("commits: serving HTML -", html.length, "chars");
                return res.send(injectCustomCss(injectBaseTag(html, "/commits/")));
            }
            const buf = Buffer.from(await upstream.arrayBuffer());
            res.setHeader("Content-Type", contentType);
            log("commits: serving raw body -", buf.length, "bytes,", contentType);
            res.send(buf);
        } catch (e) {
            errlog("commits: FAILED -", e.stack || e.message);
            if (!res.headersSent) res.status(502).send("Proxy Error");
        }
    });
}