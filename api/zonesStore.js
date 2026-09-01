import fs from "fs";
import path from "path";
const ZONE_KEY_PREFIX = "zone:";
const SOURCE_CACHE_TTL_MS = 10 * 60 * 1000;
const FETCH_TIMEOUT_MS = 15000;
const CUSTOM_GAME_CSS = `
    html, body {
        margin: 0;
        padding: 0;
        width: 100%;
        height: 100%;
        background: #0b0b0f;
        overflow: hidden;
    }
    #zoneFrame {
        height: 100% !important;
        width: 100% !important;
    }
    .zone-header {
        display:none;
    }
    #sidebarad1, #sidebarad2 {
        display:none !important;
    }
`;
function log(sourceId, ...args) {
    console.log(`[gameSource:${sourceId || "-"}]`, ...args);
}
function errlog(sourceId, ...args) {
    console.error(`[gameSource:${sourceId || "-"}]`, ...args);
}
let cachedSources = null;
function splitEnvList(...vals) {
    return vals.filter(Boolean);
}
function buildZoneSource() {
    const id = process.env.GAME_SOURCE_ZONE_ID || "zone";
    const name = process.env.GAMES_1_NAME || process.env.GAME_SOURCE_ZONE_NAME || "Zone";
    const manifestUrls = splitEnvList(process.env.ZONE1, process.env.ZONE2, process.env.ZONE3);
    let gameBases = splitEnvList(process.env.GAME_BASE1, process.env.GAME_BASE2, process.env.GAME_BASE3);
    if (!gameBases.length && process.env.GAME_BASE) gameBases = [process.env.GAME_BASE];
    const coverBase = process.env.COVER_BASE || "";
    if (!manifestUrls.length) {
        console.warn("gameSources: ZONE1/ZONE2/ZONE3 not set in env - the zone source will be empty");
    }
    if (!gameBases.length) {
        console.warn("gameSources: GAME_BASE1/GAME_BASE2/GAME_BASE3 (or GAME_BASE) not set in env - zone game proxying will fail");
    }
    return { id, name, kind: "zone", manifestUrls, gameBases, coverBase };
}
function buildManifestSources() {
    const sources = [];
    for (let n = 2; n <= 8; n++) {
        const legacyPrefix = `GAME_SOURCE${n}_`;
        let bases = splitEnvList(
            process.env[`GAME_SOURCE${n}`],
            process.env[`GAME_SOURCE${n}_2`],
            process.env[`GAME_SOURCE${n}_3`]
        );
        if (!bases.length) {
            bases = splitEnvList(
                process.env[`${legacyPrefix}BASE1`],
                process.env[`${legacyPrefix}BASE2`],
                process.env[`${legacyPrefix}BASE3`]
            );
            if (!bases.length && process.env[`${legacyPrefix}BASE`]) bases = [process.env[`${legacyPrefix}BASE`]];
        }
        let manifestUrls = splitEnvList(
            process.env[`GAME${n}_ZONE`],
            process.env[`GAME${n}_ZONE2`],
            process.env[`GAME${n}_ZONE3`]
        );
        if (!manifestUrls.length) {
            manifestUrls = splitEnvList(
                process.env[`${legacyPrefix}MANIFEST1`],
                process.env[`${legacyPrefix}MANIFEST2`],
                process.env[`${legacyPrefix}MANIFEST3`]
            );
        }
        if (!bases.length && manifestUrls.length === 0) continue; // this slot isn't configured, skip
        const id = process.env[`${legacyPrefix}ID`] || `source${n}`;
        const name = process.env[`GAMES_${n}_NAME`] || process.env[`${legacyPrefix}NAME`] || `Source ${n}`;
        if (!bases.length) {
            console.warn(`gameSources: GAME_SOURCE${n} (or ${legacyPrefix}BASE1/2/3) not set - source "${id}" cannot resolve game/thumbnail urls`);
        }
        if (!manifestUrls.length) {
            console.warn(`gameSources: GAME${n}_ZONE (or ${legacyPrefix}MANIFEST1 etc) not set - source "${id}" will be empty`);
        }
        sources.push({ id, name, kind: "manifest", manifestUrls, bases });
    }
    return sources;
}
function getSourcesConfig() {
    if (cachedSources) return cachedSources;
    cachedSources = [buildZoneSource(), ...buildManifestSources()];
    return cachedSources;
}
function getSource(sourceId) {
    return getSourcesConfig().find((s) => s.id === sourceId) || null;
}
function getZoneSource() {
    return getSourcesConfig().find((s) => s.kind === "zone") || null;
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
                await new Promise((r) => setTimeout(r, 500));
            }
        }
    }
    throw lastErr;
}
function getHostForBase(base) {
    try {
        return new URL(base).hostname;
    } catch {
        return "";
    }
}
let activeBaseIndexBySource = new Map();
async function fetchFromBases(source, bases, buildTarget, { retries = 1 } = {}) {
    if (!bases.length) {
        throw Object.assign(new Error("No Game Bases Configured"), { status: 500 });
    }
    let activeIdx = activeBaseIndexBySource.get(source.id) || 0;
    let lastErr = null;
    for (let i = 0; i < bases.length; i++) {
        const idx = (activeIdx + i) % bases.length;
        const base = bases[idx];
        let target, fetchUrl;
        try {
            ({ target, fetchUrl } = buildTarget(base));
        } catch (e) {
            log(source.id, "bad path for base", base, "-", e.message);
            lastErr = Object.assign(new Error("Bad Path"), { status: 400 });
            continue;
        }
        const host = getHostForBase(base);
        if (!host || target.hostname !== host) {
            log(source.id, "BLOCKED, hostname", target.hostname, "!=", host, "for base", base);
            lastErr = Object.assign(new Error("Blocked"), { status: 403 });
            continue;
        }
        if (target.protocol !== "https:" && target.protocol !== "http:") {
            log(source.id, "bad protocol", target.protocol, "for base", base);
            lastErr = Object.assign(new Error("Bad Path"), { status: 400 });
            continue;
        }
        try {
            const upstream = await fetchWithRetry(fetchUrl, {
                redirect: "follow",
                headers: { "User-Agent": "Mozilla/5.0 (compatible; InfiniteCampusGameProxy/1.0)" },
            }, retries);
            if (!upstream.ok && upstream.status !== 304) {
                log(source.id, "base", base, "returned status", upstream.status, "for", fetchUrl, "- trying next base");
                lastErr = Object.assign(new Error("Upstream Error"), { status: upstream.status });
                continue;
            }
            if (idx !== activeIdx) {
                log(source.id, "switching active game base from", bases[activeIdx], "to", base);
                activeBaseIndexBySource.set(source.id, idx);
            }
            return { upstream, base, fetchUrl };
        } catch (e) {
            errlog(source.id, "upstream fetch threw for base", base, "-", e.message, "- trying next base");
            lastErr = Object.assign(new Error(e.message || "Proxy Error"), { status: 502 });
        }
    }
    throw lastErr || Object.assign(new Error("All Game Bases Failed"), { status: 502 });
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
function sourceDir(__dirname, sourceId) {
    return path.join(__dirname, "data", "games", sourceId);
}
function gamesJsonPath(__dirname, sourceId) {
    return path.join(sourceDir(__dirname, sourceId), "games.json");
}
function hiddenJsonPath(__dirname, sourceId) {
    return path.join(sourceDir(__dirname, sourceId), "hidden.json");
}
function ensureSourceFiles(__dirname, sourceId) {
    const dir = sourceDir(__dirname, sourceId);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const gamesPath = gamesJsonPath(__dirname, sourceId);
    if (!fs.existsSync(gamesPath)) fs.writeFileSync(gamesPath, JSON.stringify({}, null, 2));
    const hiddenPath = hiddenJsonPath(__dirname, sourceId);
    if (!fs.existsSync(hiddenPath)) fs.writeFileSync(hiddenPath, JSON.stringify([], null, 2));
}
function loadHiddenJSON(__dirname, sourceId) {
    try {
        const arr = JSON.parse(fs.readFileSync(hiddenJsonPath(__dirname, sourceId), "utf8"));
        return Array.isArray(arr) ? arr.map(String) : [];
    } catch {
        return [];
    }
}
function saveHiddenJSON(__dirname, sourceId, hidden) {
    fs.writeFileSync(hiddenJsonPath(__dirname, sourceId), JSON.stringify(hidden.map(String).filter(Boolean), null, 2));
}
function loadGamesJSON(__dirname, sourceId) {
    try {
        return JSON.parse(fs.readFileSync(gamesJsonPath(__dirname, sourceId), "utf8"));
    } catch {
        return {};
    }
}
function saveGamesJSON(__dirname, sourceId, games) {
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
    fs.writeFileSync(gamesJsonPath(__dirname, sourceId), JSON.stringify(merged, null, 2));
}
function getHiddenIdSet(__dirname, sourceId, games) {
    let hidden = loadHiddenJSON(__dirname, sourceId);
    if (hidden.length === 0 && Array.isArray(games._hidden) && games._hidden.length > 0) {
        hidden = games._hidden.map(String);
        saveHiddenJSON(__dirname, sourceId, hidden);
    }
    return new Set(hidden);
}
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
function isValidManifestGame(g) {
    return (
        g &&
        typeof g === "object" &&
        typeof g.name === "string" &&
        g.name.trim().length > 0 &&
        typeof g.url === "string" &&
        g.url.trim().length > 0
    );
}
function hashId(str) {
    let h = 5381;
    for (let i = 0; i < str.length; i++) {
        h = ((h * 33) ^ str.charCodeAt(i)) >>> 0;
    }
    return h.toString(36);
}
function zoneKey(id) {
    return `${ZONE_KEY_PREFIX}${id}`;
}
async function fetchRawFeed(source) {
    let lastErr = null;
    for (const url of source.manifestUrls) {
        log(source.id, "fetching feed from", url);
        try {
            const res = await fetchWithTimeout(url, {
                headers: { "User-Agent": "Mozilla/5.0 (compatible; InfiniteCampusGameFeedFetch/1.0)" },
            });
            if (!res.ok) throw new Error(`Bad Status ${res.status}`);
            const json = await res.json();
            if (source.kind === "zone") {
                if (!Array.isArray(json)) throw new Error("Invalid Zone Feed Format (expected array)");
                log(source.id, "feed fetch OK from", url, "entries:", json.length);
                return json;
            }
            const games = Array.isArray(json?.games) ? json.games : null;
            if (!games) throw new Error("Invalid Manifest Feed Format (expected { games: [...] })");
            log(source.id, "feed fetch OK from", url, "entries:", games.length);
            return games;
        } catch (e) {
            log(source.id, "feed fetch FAILED from", url, "-", e.message);
            lastErr = e;
        }
    }
    throw lastErr || new Error("Failed To Fetch Feed");
}
function buildZoneList(zones, games) {
    const valid = zones.filter(isValidZoneGame);
    return valid.map((z) => {
        const key = zoneKey(z.id);
        if (!games[key]) games[key] = { popularity: 0, dateAdded: Date.now() };
        const stored = games[key];
        return {
            id: String(z.id),
            name: z.name,
            author: z.author || null,
            authorLink: typeof z.authorLink === "string" && z.authorLink ? z.authorLink : null,
            hasThumbnail: true,
            frameType: "zone",
            popularity: stored.popularity || 0,
            dateAdded: stored.dateAdded || null,
        };
    });
}
function buildManifestList(entries, games) {
    const valid = entries.filter(isValidManifestGame);
    return valid.map((g) => {
        const id = hashId(g.url);
        if (!games[id]) games[id] = { popularity: 0, dateAdded: Date.now() };
        const stored = games[id];
        stored.url = g.url;
        stored.thumbnail = typeof g.thumbnail === "string" ? g.thumbnail : null;
        stored.frameType = typeof g.frameType === "string" && g.frameType ? g.frameType : "iframe";
        stored.name = g.name;
        games[id] = stored;
        return {
            id,
            name: g.name,
            author: null,
            authorLink: null,
            hasThumbnail: !!stored.thumbnail,
            frameType: stored.frameType,
            popularity: stored.popularity || 0,
            dateAdded: stored.dateAdded || null,
        };
    });
}
const feedCache = new Map();
const inFlightFetch = new Map();
const refreshTimers = new Map();
async function getRawFeed(source) {
    const cached = feedCache.get(source.id);
    if (cached?.data) return cached.data;
    if (inFlightFetch.has(source.id)) return inFlightFetch.get(source.id);
    const p = fetchRawFeed(source)
        .then((data) => {
            feedCache.set(source.id, { data, fetchedAt: Date.now() });
            return data;
        })
        .finally(() => { inFlightFetch.delete(source.id); });
    inFlightFetch.set(source.id, p);
    return p;
}
async function refreshRawFeed(source) {
    const data = await fetchRawFeed(source);
    feedCache.set(source.id, { data, fetchedAt: Date.now() });
    return data;
}
function startRefreshLoop(source, deps) {
    if (refreshTimers.has(source.id)) return;
    const timer = setInterval(async () => {
        try {
            await mergeSourceIntoGamesJSON(source, deps);
            log(source.id, "background refresh: source updated");
        } catch (e) {
            errlog(source.id, "background refresh FAILED, continuing to serve stale/cached data -", e.message);
        }
    }, SOURCE_CACHE_TTL_MS);
    if (timer.unref) timer.unref();
    refreshTimers.set(source.id, timer);
}
async function mergeSourceIntoGamesJSON(source, deps) {
    const { __dirname } = deps;
    const raw = await refreshRawFeed(source);
    const games = loadGamesJSON(__dirname, source.id);
    const list = source.kind === "zone" ? buildZoneList(raw, games) : buildManifestList(raw, games);
    games._list = list;
    saveGamesJSON(__dirname, source.id, games);
    log(source.id, "merged", list.length, "games into", `data/games/${source.id}/games.json`);
    return list;
}
export async function initZoneGames(deps) {
    const sources = getSourcesConfig();
    for (const source of sources) {
        ensureSourceFiles(deps.__dirname, source.id);
        try {
            await mergeSourceIntoGamesJSON(source, deps);
            log(source.id, "startup feed fetch + merge succeeded");
        } catch (e) {
            errlog(source.id, "startup feed fetch FAILED -", e.message, "- serving existing games.json (if any) until the next refresh succeeds");
        }
        startRefreshLoop(source, deps);
    }
}
function isAdminPass(req) {
    const pass = req.headers["x-admin-password"];
    return pass === process.env.ADMIN_PASSWORD || pass === process.env.ADMIN_PASSWORD_2;
}
function shuffle(arr) {
    const out = arr.slice();
    for (let i = out.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [out[i], out[j]] = [out[j], out[i]];
    }
    return out;
}
function requireSource(req, res) {
    const source = getSource(req.params.sourceId);
    if (!source) {
        res.status(404).json({ ok: false, error: "Unknown Game Source" });
        return null;
    }
    return source;
}
export function attachZoneGameRoutes(app, deps) {
    const { __dirname } = deps;
    const sources = getSourcesConfig();
    for (const source of sources) ensureSourceFiles(__dirname, source.id);

    app.get("/game-sources", (req, res) => {
        res.json({ ok: true, sources: getSourcesConfig().map((s) => ({ id: s.id, name: s.name })) });
    });
    app.get("/games/popular", async (req, res) => {
        res.setHeader("Cache-Control", "public, max-age=60, stale-while-revalidate=300");
        try {
            const allSources = getSourcesConfig();
            let combined = [];
            for (const source of allSources) {
                const games = loadGamesJSON(__dirname, source.id);
                const hidden = getHiddenIdSet(__dirname, source.id, games);
                const list = Array.isArray(games._list) ? games._list.filter((g) => !hidden.has(String(g.id))) : [];
                for (const g of list) {
                    combined.push({ ...g, sourceId: source.id, sourceName: source.name });
                }
            }
            combined.sort((a, b) => (b.popularity || 0) - (a.popularity || 0));
            const top = combined.slice(0, 5);
            log("popular", "serving top", top.length, "popular games out of", combined.length, "total");
            res.json({ ok: true, games: top });
        } catch (e) {
            errlog("popular", "top games FAILED -", e.stack || e.message);
            res.status(502).json({ ok: false, error: "Failed To Load Popular Games" });
        }
    });
    app.get("/games/:sourceId", async (req, res) => {
        const source = requireSource(req, res);
        if (!source) return;
        res.setHeader("Cache-Control", "public, max-age=60, stale-while-revalidate=300");
        try {
            const games = loadGamesJSON(__dirname, source.id);
            const hidden = getHiddenIdSet(__dirname, source.id, games);
            const list = Array.isArray(games._list) ? games._list.filter((g) => !hidden.has(String(g.id))) : [];
            log(source.id, "serving list -", list.length, "games (", hidden.size, "hidden)");
            res.json({ ok: true, games: shuffle(list) });
        } catch (e) {
            errlog(source.id, "list FAILED -", e.stack || e.message);
            res.status(502).json({ ok: false, error: "Failed To Load Games" });
        }
    });
    app.post("/admin/games/:sourceId/regenerate", async (req, res) => {
        const source = requireSource(req, res);
        if (!source) return;
        if (!isAdminPass(req)) return res.status(403).json({ ok: false, error: "Not Allowed" });
        try {
            const list = await mergeSourceIntoGamesJSON(source, deps);
            log(source.id, "/admin/games/:sourceId/regenerate forced a fresh fetch, entries:", list.length);
            res.json({ ok: true, count: list.length });
        } catch (e) {
            errlog(source.id, "regenerate FAILED -", e.stack || e.message);
            res.status(500).json({ ok: false, error: "Failed To Refresh Source" });
        }
    });
    app.get("/admin/games-json/:sourceId", (req, res) => {
        const source = requireSource(req, res);
        if (!source) return;
        if (!isAdminPass(req)) return res.status(403).json({ ok: false, error: "Not Allowed" });
        try {
            res.json({ ok: true, games: loadGamesJSON(__dirname, source.id) });
        } catch (e) {
            errlog(source.id, "games-json GET FAILED -", e.stack || e.message);
            res.status(500).json({ ok: false, error: "Failed To Load games.json" });
        }
    });
    app.post("/admin/games-json/:sourceId", (req, res) => {
        const source = requireSource(req, res);
        if (!source) return;
        if (!isAdminPass(req)) return res.status(403).json({ ok: false, error: "Not Allowed" });
        try {
            const { games } = req.body || {};
            if (!games || typeof games !== "object" || Array.isArray(games)) {
                return res.status(400).json({ ok: false, error: "Invalid games.json Payload" });
            }
            saveGamesJSON(__dirname, source.id, games);
            log(source.id, "games-json saved via admin edit -", Object.keys(games).length, "top-level keys");
            res.json({ ok: true });
        } catch (e) {
            errlog(source.id, "games-json POST FAILED -", e.stack || e.message);
            res.status(500).json({ ok: false, error: "Failed To Save games.json" });
        }
    });
    app.get("/admin/hidden-games/:sourceId", (req, res) => {
        const source = requireSource(req, res);
        if (!source) return;
        if (!isAdminPass(req)) return res.status(403).json({ ok: false, error: "Not Allowed" });
        try {
            const games = loadGamesJSON(__dirname, source.id);
            const hidden = [...getHiddenIdSet(__dirname, source.id, games)];
            res.json({ ok: true, hidden });
        } catch (e) {
            errlog(source.id, "hidden-games GET FAILED -", e.stack || e.message);
            res.status(500).json({ ok: false, error: "Failed To Load Hidden Games" });
        }
    });
    app.post("/admin/hidden-games/:sourceId", (req, res) => {
        const source = requireSource(req, res);
        if (!source) return;
        if (!isAdminPass(req)) return res.status(403).json({ ok: false, error: "Not Allowed" });
        try {
            const { hidden } = req.body || {};
            if (!Array.isArray(hidden)) return res.status(400).json({ ok: false, error: "Invalid Hidden List" });
            const cleaned = hidden.map(String).filter(Boolean);
            saveHiddenJSON(__dirname, source.id, cleaned);
            const games = loadGamesJSON(__dirname, source.id);
            if (games._hidden) {
                delete games._hidden;
                saveGamesJSON(__dirname, source.id, games);
            }
            log(source.id, "hidden-games saved -", cleaned.length, "hidden id(s)");
            res.json({ ok: true, hidden: cleaned });
        } catch (e) {
            errlog(source.id, "hidden-games POST FAILED -", e.stack || e.message);
            res.status(500).json({ ok: false, error: "Failed To Save Hidden Games" });
        }
    });
    const popularityDebounce = new Map();
    app.post("/games/:sourceId/:id/popularity", async (req, res) => {
        const source = requireSource(req, res);
        if (!source) return;
        const id = req.params.id;
        try {
            const games = loadGamesJSON(__dirname, source.id);
            let key, exists;
            if (source.kind === "zone") {
                if (!/^\d+$/.test(id)) return res.status(400).json({ ok: false, error: "Invalid Id" });
                const zones = await getRawFeed(source);
                exists = zones.find((z) => String(z.id) === id && isValidZoneGame(z));
                key = zoneKey(id);
            } else {
                exists = games[id];
                key = id;
            }
            if (!exists) return res.status(404).json({ ok: false, error: "Not Found" });
            if (!games[key]) games[key] = { popularity: 0, dateAdded: Date.now() };
            const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket?.remoteAddress || "unknown";
            const dkey = `${source.id}:${ip}:${id}`;
            const now = Date.now();
            const last = popularityDebounce.get(dkey) || 0;
            if (now - last > 10_000) {
                games[key].popularity = (games[key].popularity || 0) + 1;
                popularityDebounce.set(dkey, now);
                if (Array.isArray(games._list)) {
                    const entry = games._list.find((g) => String(g.id) === id);
                    if (entry) entry.popularity = games[key].popularity;
                }
                saveGamesJSON(__dirname, source.id, games);
                log(source.id, "popularity bumped id", id, "to", games[key].popularity);
            }
            res.json({ ok: true, popularity: games[key].popularity });
        } catch (e) {
            errlog(source.id, "popularity FAILED for id", id, "-", e.stack || e.message);
            res.status(500).json({ ok: false });
        }
    });
    app.get("/games/:sourceId/:id/thumbnail", async (req, res) => {
        const source = requireSource(req, res);
        if (!source) return;
        const id = req.params.id;
        try {
            let thumbUrl;
            if (source.kind === "zone") {
                if (!/^\d+$/.test(id)) return res.status(400).send("Bad Request");
                const zones = await getRawFeed(source);
                const z = zones.find((z) => String(z.id) === id && isValidZoneGame(z));
                if (!z) return res.status(404).send("Not Found");
                thumbUrl = `${source.coverBase}/${encodeURIComponent(id)}.png`;
            } else {
                const games = loadGamesJSON(__dirname, source.id);
                const entry = games[id];
                if (!entry || !entry.thumbnail) return res.status(404).send("Not Found");
                if (!source.bases.length) return res.status(404).send("Not Found");
                thumbUrl = new URL(entry.thumbnail, source.bases[0] + "/").toString();
            }
            let upstream;
            try {
                upstream = await fetchWithTimeout(thumbUrl, {
                    headers: { "User-Agent": "Mozilla/5.0 (compatible; InfiniteCampusThumbProxy/1.0)" },
                });
            } catch (e) {
                errlog(source.id, "thumbnail upstream fetch threw for id", id, "-", e.message);
                return res.status(502).send("Proxy Error");
            }
            if (!upstream.ok) return res.status(404).send("Not Found");
            const contentType = upstream.headers.get("content-type") || "image/png";
            res.setHeader("Content-Type", contentType.startsWith("image/") ? contentType : "image/png");
            res.setHeader("X-Content-Type-Options", "nosniff");
            res.setHeader("Cache-Control", "public, max-age=604800, stale-while-revalidate=2592000, immutable");
            const buf = Buffer.from(await upstream.arrayBuffer());
            res.send(buf);
        } catch (e) {
            errlog(source.id, "thumbnail FAILED for id", id, "-", e.stack || e.message);
            if (!res.headersSent) res.status(502).send("Proxy Error");
        }
    });
    app.get("/games/:sourceId/:id{/*rest}", async (req, res) => {
        const source = requireSource(req, res);
        if (!source) return;
        const id = req.params.id;
        const rest = Array.isArray(req.params.rest) ? req.params.rest.join("/") : req.params.rest || "";
        log(source.id, "GET", `/games/${source.id}/${id}${rest ? "/" + rest : ""}`, "from", req.ip);
        try {
            let upstream, fetchUrl, basePath;
            if (source.kind === "zone") {
                if (!/^\d+$/.test(id)) return res.status(404).send("Not Found");
                const zones = await getRawFeed(source);
                const z = zones.find((z) => String(z.id) === id && isValidZoneGame(z));
                if (!z) return res.status(404).send("Not Found");
                try {
                    ({ upstream, fetchUrl } = await fetchFromBases(source, source.gameBases, (base) => {
                        if (rest) {
                            const target = new URL(rest, base + "/");
                            return { target, fetchUrl: target.toString() };
                        }
                        const url = `${base}?id=${encodeURIComponent(id)}`;
                        return { target: new URL(url), fetchUrl: url };
                    }));
                } catch (e) {
                    const status = e.status || 502;
                    const msg = status === 400 ? "Bad Path" : status === 403 ? "Blocked" : status === 502 ? "Proxy Error" : "Upstream Error";
                    return res.status(status).send(msg);
                }
                basePath = `/games/${source.id}/${encodeURIComponent(id)}/`;
            } else {
                const games = loadGamesJSON(__dirname, source.id);
                const entry = games[id];
                if (!entry || !entry.url) return res.status(404).send("Not Found");
                try {
                    ({ upstream, fetchUrl } = await fetchFromBases(source, source.bases, (base) => {
                        const target = rest ? new URL(rest, new URL(entry.url, base + "/")) : new URL(entry.url, base + "/");
                        return { target, fetchUrl: target.toString() };
                    }));
                } catch (e) {
                    const status = e.status || 502;
                    const msg = status === 400 ? "Bad Path" : status === 403 ? "Blocked" : status === 502 ? "Proxy Error" : "Upstream Error";
                    return res.status(status).send(msg);
                }
                basePath = `/games/${source.id}/${encodeURIComponent(id)}/`;
            }
            const contentType = upstream.headers.get("content-type") || "application/octet-stream";
            res.setHeader("X-Content-Type-Options", "nosniff");
            res.setHeader("Cache-Control", "public, max-age=300");
            if (contentType.includes("text/html")) {
                const html = await upstream.text();
                res.setHeader("Content-Type", "text/html; charset=utf-8");
                const withBase = injectBaseTag(html, basePath);
                const finalHtml = source.kind === "zone" ? injectCustomCss(withBase) : withBase;
                return res.send(finalHtml);
            }
            res.setHeader("Content-Type", contentType);
            const buf = Buffer.from(await upstream.arrayBuffer());
            res.send(buf);
        } catch (e) {
            errlog(source.id, "games proxy FAILED for id", id, "-", e.stack || e.message);
            if (!res.headersSent) res.status(502).send("Proxy Error");
        }
    });
    app.get("/commits", async (req, res) => {
        const zoneSource = getZoneSource();
        if (!zoneSource) return res.status(404).send("Not Found");
        log(zoneSource.id, "GET /commits from", req.ip);
        try {
            let upstream, fetchUrl;
            try {
                ({ upstream, fetchUrl } = await fetchFromBases(zoneSource, zoneSource.gameBases, (base) => {
                    const url = `${base}/commits`;
                    return { target: new URL(url), fetchUrl: url };
                }));
            } catch (e) {
                const status = e.status || 502;
                const msg = status === 400 ? "Bad Path" : status === 403 ? "Blocked" : status === 502 ? "Proxy Error" : "Upstream Error";
                return res.status(status).send(msg);
            }
            const contentType = upstream.headers.get("content-type") || "application/octet-stream";
            res.setHeader("X-Content-Type-Options", "nosniff");
            res.setHeader("Cache-Control", "public, max-age=60");
            if (contentType.includes("application/json")) {
                const json = await upstream.text();
                res.setHeader("Content-Type", "application/json; charset=utf-8");
                return res.send(json);
            }
            if (contentType.includes("text/html")) {
                const html = await upstream.text();
                res.setHeader("Content-Type", "text/html; charset=utf-8");
                return res.send(injectCustomCss(injectBaseTag(html, "/commits/")));
            }
            const buf = Buffer.from(await upstream.arrayBuffer());
            res.setHeader("Content-Type", contentType);
            res.send(buf);
        } catch (e) {
            errlog(zoneSource.id, "commits FAILED -", e.stack || e.message);
            if (!res.headersSent) res.status(502).send("Proxy Error");
        }
    });
}