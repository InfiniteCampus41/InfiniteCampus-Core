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
    const now = Date.now();
    if (zoneCache.data && now - zoneCache.fetchedAt < ZONE_CACHE_TTL_MS) {
        log("getZones: serving cached zones, age", Math.round((now - zoneCache.fetchedAt) / 1000), "s, entries:", zoneCache.data.length);
        return zoneCache.data;
    }
    if (inFlightFetch) {
        log("getZones: awaiting in-flight fetch");
        return inFlightFetch;
    }
    log("getZones: cache stale/empty, refreshing");
    inFlightFetch = (async () => {
        try {
            const data = await fetchZonesFresh();
            zoneCache = { data, fetchedAt: Date.now() };
            return data;
        } catch (e) {
            log("getZones: refresh failed -", e.message, zoneCache.data ? "(serving stale cache)" : "(no cache to fall back on)");
            if (zoneCache.data) return zoneCache.data;
            throw e;
        } finally {
            inFlightFetch = null;
        }
    })();
    return inFlightFetch;
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
export function attachZoneGameRoutes(app, deps) {
    const { __dirname } = deps;
    const GAMES_JSON = path.join(__dirname, "games.json");
    if (!fs.existsSync(GAMES_JSON)) fs.writeFileSync(GAMES_JSON, JSON.stringify({}, null, 2));
    function loadGamesJSON() {
        try {
            return JSON.parse(fs.readFileSync(GAMES_JSON, "utf8"));
        } catch {
            return {};
        }
    }
    function saveGamesJSON(games) {
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
    app.get("/api/zone-games", async (req, res) => {
        log("GET /api/zone-games from", req.ip);
        res.setHeader("Cache-Control", "public, max-age=60, stale-while-revalidate=300");
        try {
            const cached = loadGamesJSON();
            if (Array.isArray(cached._list) && cached._list.length) {
                log("zone-games: serving cached list from games.json -", cached._list.length, "games");
                return res.json({ ok: true, games: shuffle(cached._list) });
            }
            log("zone-games: no cached list yet, generating from zones feed");
            const zones = await getZones();
            const valid = zones.filter(isValidZoneGame);
            log("zone-games: total zones", zones.length, "valid", valid.length);
            const games = loadGamesJSON();
            const list = valid.map((z) => {
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
            games._list = list;
            log("zone-games: persisting generated list of", list.length, "games to games.json");
            saveGamesJSON(games);
            log("zone-games: responding with", list.length, "games");
            res.json({ ok: true, games: shuffle(list) });
        } catch (e) {
            console.error("Zone Games List Error:", e.message);
            log("zone-games: FAILED -", e.stack || e.message);
            res.status(502).json({ ok: false, error: "Failed To Load Games" });
        }
    });
    app.post("/admin/zone-games/regenerate", (req, res) => {
        const pass = req.headers["x-admin-password"];
        if (pass !== process.env.ADMIN_PASSWORD && pass !== process.env.ADMIN_PASSWORD_2) {
            return res.status(403).json({ ok: false, error: "Not Allowed" });
        }
        try {
            const games = loadGamesJSON();
            delete games._list;
            saveGamesJSON(games);
            log("zone-games: cached list cleared via /admin/zone-games/regenerate, will regenerate on next request");
            res.json({ ok: true });
        } catch (e) {
            log("zone-games: regenerate FAILED -", e.stack || e.message);
            res.status(500).json({ ok: false, error: "Failed To Clear Cache" });
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
            const games = loadGamesJSON();
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
                saveGamesJSON(games);
                log("popularity: bumped id", id, "to", games[key].popularity);
            } else {
                log("popularity: debounced for id", id, "(", ip, ")");
            }
            res.json({ ok: true, popularity: games[key].popularity });
        } catch (e) {
            log("popularity: FAILED for id", id, "-", e.stack || e.message);
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
                log("thumbnail: upstream fetch threw for id", id, "-", e.message);
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
            log("thumbnail: FAILED for id", id, "-", e.stack || e.message);
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
                upstream = await fetchWithTimeout(fetchUrl, {
                    redirect: "follow",
                    headers: { "User-Agent": "Mozilla/5.0 (compatible; InfiniteCampusGameProxy/1.0)" },
                });
            } catch (e) {
                log("games proxy: upstream fetch threw for", fetchUrl, "-", e.message);
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
            log("games proxy: FAILED for id", id, "-", e.stack || e.message);
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
                log("commits: upstream fetch threw -", e.message);
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
            log("commits: FAILED -", e.stack || e.message);
            if (!res.headersSent) res.status(502).send("Proxy Error");
        }
    });
}