import fs from "fs";
import path from "path";
import multer from "multer";
import AdmZip from "adm-zip";
const EXT_BY_TYPE = { html5: ".zip", flash: ".swf" };
const MAX_GAME_UPLOAD_BYTES = 50 * 1024 * 1024;
const MAX_THUMB_BYTES = 5 * 1024 * 1024;
const MAX_ZIP_UNCOMPRESSED_BYTES = 300 * 1024 * 1024;
const MAX_ZIP_ENTRIES = 10000;
const MAX_NAME_LEN = 100;
const MAX_DESC_LEN = 2000;
const MAX_URL_LEN = 2000;
const PROXY_FETCH_TIMEOUT_MS = 15000;
const RUFFLE_SCRIPT_URL = "https://unpkg.com/@ruffle-rs/ruffle";
const MIME_BY_EXT = {
    ".html": "text/html; charset=utf-8",
    ".htm": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".mjs": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".svg": "image/svg+xml",
    ".webp": "image/webp",
    ".ico": "image/x-icon",
    ".mp3": "audio/mpeg",
    ".ogg": "audio/ogg",
    ".oga": "audio/ogg",
    ".wav": "audio/wav",
    ".mp4": "video/mp4",
    ".webm": "video/webm",
    ".wasm": "application/wasm",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".ttf": "font/ttf",
    ".otf": "font/otf",
    ".txt": "text/plain; charset=utf-8",
    ".xml": "application/xml; charset=utf-8",
    ".data": "application/octet-stream",
};
function mimeFor(fileName) {
    return MIME_BY_EXT[path.extname(fileName).toLowerCase()] || "application/octet-stream";
}
function detectMagic(buf) {
    if (buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x4b && (buf[2] === 0x03 || buf[2] === 0x05 || buf[2] === 0x07)) {
        return "zip";
    }
    const sig3 = buf.slice(0, 3).toString("ascii");
    if (sig3 === "FWS" || sig3 === "CWS" || sig3 === "ZWS") return "swf";
    return null;
}
function detectImageExt(buf) {
    if (buf.length >= 8 && buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) return ".png";
    if (buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return ".jpg";
    if (buf.length >= 6) {
        const sig6 = buf.slice(0, 6).toString("ascii");
        if (sig6 === "GIF87a" || sig6 === "GIF89a") return ".gif";
    }
    if (buf.length >= 12 && buf.slice(0, 4).toString("ascii") === "RIFF" && buf.slice(8, 12).toString("ascii") === "WEBP") return ".webp";
    return null;
}
function validateThumbnailBuffer(buffer) {
    if (!buffer || !buffer.length) throw new Error("Thumbnail Is Empty");
    if (buffer.length > MAX_THUMB_BYTES) throw new Error("Thumbnail Exceeds The 5MB Limit");
    const ext = detectImageExt(buffer);
    if (!ext) throw new Error("Thumbnail Must Be A PNG, JPG, GIF, Or WEBP Image");
    return ext;
}
function sanitizeFolderName(name, sanitize) {
    const base = sanitize(String(name || "").trim()).replace(/\s+/g, " ").trim();
    return base || "game";
}
function uniqueFolderName(baseDir, wantedName, sanitize) {
    const clean = sanitizeFolderName(wantedName, sanitize);
    let candidate = clean;
    let n = 2;
    while (fs.existsSync(path.join(baseDir, candidate))) {
        candidate = `${clean} (${n})`;
        n++;
    }
    return candidate;
}
function formatBytesLocal(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
    return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}
function validateZipBuffer(buffer, { requireIndexHtml }) {
    let zip;
    try {
        zip = new AdmZip(buffer);
    } catch {
        throw new Error("File Is Not A Valid Zip Archive");
    }
    const entries = zip.getEntries();
    if (entries.length === 0) throw new Error("Zip Archive Is Empty");
    if (entries.length > MAX_ZIP_ENTRIES) throw new Error("Zip Archive Has Too Many Files");
    let totalUncompressed = 0;
    let hasIndexHtml = false;
    for (const entry of entries) {
        const name = entry.entryName.replace(/\\/g, "/");
        if (name.split("/").includes("..") || name.startsWith("/") || /^[a-zA-Z]:/.test(name)) {
            throw new Error("Zip Archive Contains Unsafe Paths");
        }
        const unixMode = (entry.header.attr >>> 16) & 0xffff;
        const isSymlink = (unixMode & 0xa000) === 0xa000;
        if (isSymlink) throw new Error("Zip Archive Contains Symlinks, Which Are Not Allowed");
        totalUncompressed += entry.header.size;
        if (totalUncompressed > MAX_ZIP_UNCOMPRESSED_BYTES) throw new Error("Zip Archive Is Too Large When Extracted");
        if (!entry.isDirectory && (name === "index.html" || name.toLowerCase() === "index.html")) {
            hasIndexHtml = true;
        }
    }
    if (requireIndexHtml && !hasIndexHtml) {
        throw new Error("HTML5 Game Zip Must Contain An index.html File At Its Root");
    }
    return zip;
}
const BLOCKED_HOSTNAMES = new Set(["localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]"]);
function isPrivateHostname(hostname) {
    const h = (hostname || "").toLowerCase();
    if (BLOCKED_HOSTNAMES.has(h)) return true;
    if (/^10\./.test(h)) return true;
    if (/^192\.168\./.test(h)) return true;
    if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return true;
    if (/^169\.254\./.test(h)) return true;
    if (h.endsWith(".local")) return true;
    return false;
}
function validateGameUrl(raw) {
    const trimmed = String(raw || "").trim();
    if (!trimmed) throw new Error("Game URL Is Required");
    if (trimmed.length > MAX_URL_LEN) throw new Error("URL Is Too Long");
    let u;
    try {
        u = new URL(trimmed);
    } catch {
        throw new Error("Invalid URL");
    }
    if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("URL Must Use HTTP Or HTTPS");
    if (isPrivateHostname(u.hostname)) throw new Error("This URL Is Not Allowed");
    return u.toString();
}
const zipCache = new Map();
function getZipForGame(cacheKey, filePath) {
    const stat = fs.statSync(filePath);
    const cached = zipCache.get(cacheKey);
    if (cached && cached.mtimeMs === stat.mtimeMs) return cached.zip;
    const zip = new AdmZip(filePath);
    zipCache.set(cacheKey, { mtimeMs: stat.mtimeMs, zip });
    return zip;
}
function injectBaseTag(html, baseHref) {
    if (/<base(?=[\s/>])/i.test(html)) return html;
    const tag = `<base href="${baseHref}">`;
    const headOpenMatch = html.match(/<head[^>]*>/i);
    if (headOpenMatch) {
        const idx = headOpenMatch.index + headOpenMatch[0].length;
        return html.slice(0, idx) + tag + html.slice(idx);
    }
    const htmlOpenMatch = html.match(/<html[^>]*>/i);
    if (htmlOpenMatch) {
        const idx = htmlOpenMatch.index + htmlOpenMatch[0].length;
        return html.slice(0, idx) + `<head>${tag}</head>` + html.slice(idx);
    }
    return tag + html;
}
function buildRufflePlayerHtml(swfHref) {
    return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Game</title>
<script src="${RUFFLE_SCRIPT_URL}"></script>
<style>
  html, body { margin:0; padding:0; width:100%; height:100%; background:#000; overflow:hidden; }
  #ruffle-container, #ruffle-container embed, #ruffle-container object { width:100%; height:100%; }
</style>
</head>
<body>
<div id="ruffle-container"><embed src="${swfHref}" width="100%" height="100%"></div>
</body>
</html>`;
}
function serveThumbnail(res, folder, thumbFilename) {
    if (!thumbFilename) return res.status(404).send("Not Found");
    const filePath = path.join(folder, thumbFilename);
    if (!fs.existsSync(filePath)) return res.status(404).send("Not Found");
    const type = mimeFor(thumbFilename);
    res.setHeader("Content-Type", type === "application/octet-stream" ? "image/png" : type);
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Cache-Control", "public, max-age=3600");
    fs.createReadStream(filePath).pipe(res);
}
function serveGameAsset(res, type, filePath, cacheKey, rest, basePath) {
    try {
        let entryPath = (rest || "").replace(/^\/+/, "");
        if (type === "flash") {
            const swfName = path.basename(filePath);
            if (!entryPath || entryPath.toLowerCase() === "index.html") {
                res.setHeader("Content-Type", "text/html; charset=utf-8");
                res.setHeader("X-Content-Type-Options", "nosniff");
                return res.send(buildRufflePlayerHtml(encodeURIComponent(swfName)));
            }
            if (entryPath === swfName) {
                res.setHeader("Content-Type", "application/x-shockwave-flash");
                res.setHeader("X-Content-Type-Options", "nosniff");
                return fs.createReadStream(filePath).pipe(res);
            }
            return res.status(404).send("Not Found");
        }
        const zip = getZipForGame(cacheKey, filePath);
        if (!entryPath) entryPath = "index.html";
        if (entryPath.split("/").includes("..")) return res.status(400).send("Bad Path");
        let entry = zip.getEntry(entryPath);
        if (!entry) {
            const all = zip.getEntries();
            const match = all.find((e) => e.entryName.replace(/\\/g, "/").endsWith("/" + entryPath));
            if (match) entry = match;
        }
        if (!entry || entry.isDirectory) return res.status(404).send("Not Found");
        const ext = path.extname(entryPath).toLowerCase();
        res.setHeader("Content-Type", mimeFor(entryPath));
        res.setHeader("X-Content-Type-Options", "nosniff");
        res.setHeader("Cache-Control", "public, max-age=300");
        if ((ext === ".html" || ext === ".htm") && basePath) {
            const dirParts = entryPath.split("/").slice(0, -1);
            const dirPrefix = dirParts.length ? dirParts.map(encodeURIComponent).join("/") + "/" : "";
            const baseHref = basePath + dirPrefix;
            const html = injectBaseTag(entry.getData().toString("utf8"), baseHref);
            return res.send(html);
        }
        res.send(entry.getData());
    } catch (e) {
        console.error("Game Asset Serve Error:", e);
        res.status(500).send("Server Error");
    }
}
async function serveUrlGameAsset(res, gameUrl, rest, basePath, rootAbsolute = false) {
    try {
        const entryPath = (rest || "").replace(/^\/+/, "");
        let target;
        try {
            if (rootAbsolute) {
                target = new URL("/" + entryPath, new URL(gameUrl).origin);
            } else {
                target = entryPath ? new URL(entryPath, gameUrl) : new URL(gameUrl);
            }
        } catch {
            return res.status(400).send("Bad Path");
        }
        if (target.protocol !== "http:" && target.protocol !== "https:") return res.status(400).send("Bad Path");
        if (isPrivateHostname(target.hostname)) return res.status(403).send("Blocked");
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), PROXY_FETCH_TIMEOUT_MS);
        let upstream;
        try {
            upstream = await fetch(target.toString(), {
                redirect: "follow",
                signal: controller.signal,
                headers: { "User-Agent": "Mozilla/5.0 (compatible; InfiniteCampusGameProxy/1.0)" },
            });
        } finally {
            clearTimeout(timeout);
        }
        if (!upstream.ok && upstream.status !== 304) {
            return res.status(upstream.status).send("Upstream Error");
        }
        const contentType = upstream.headers.get("content-type") || "application/octet-stream";
        res.setHeader("X-Content-Type-Options", "nosniff");
        res.setHeader("Cache-Control", "public, max-age=300");
        if (contentType.includes("text/html")) {
            const html = await upstream.text();
            const originBase = new URL(gameUrl);
            const rootDir = new URL(".", originBase);
            let relDir = "";
            const targetDir = new URL(".", target);
            if (targetDir.origin === rootDir.origin && targetDir.pathname.startsWith(rootDir.pathname)) {
                relDir = targetDir.pathname.slice(rootDir.pathname.length);
            }
            const baseHref = basePath + relDir;
            res.setHeader("Content-Type", "text/html; charset=utf-8");
            return res.send(injectBaseTag(html, baseHref));
        }
        res.setHeader("Content-Type", contentType);
        const buf = Buffer.from(await upstream.arrayBuffer());
        res.send(buf);
    } catch (e) {
        console.error("URL Game Proxy Error:", e.message);
        if (!res.headersSent) res.status(502).send("Proxy Error");
    }
}
export function attachGameRoutes(app, deps) {
    const { __dirname, discordRequest, logid, readDataPath, updateDataPath, verifyFirebaseToken, sanitize } = deps;
    const GAMES_DIR = path.join(__dirname, "games");
    const PENDING_GAMES_DIR = path.join(__dirname, "pendinggames");
    const PENDING_UPDATES_DIR = path.join(__dirname, "pendingupdates");
    const GAMES_DATA_DIR = path.join(__dirname, "data", "games");
    const GAMES_JSON = path.join(GAMES_DATA_DIR, "games.json");
    const HIDDEN_JSON = path.join(GAMES_DATA_DIR, "hidden.json");
    for (const dir of [GAMES_DIR, PENDING_GAMES_DIR, PENDING_UPDATES_DIR, GAMES_DATA_DIR]) {
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    }
    if (!fs.existsSync(GAMES_JSON)) fs.writeFileSync(GAMES_JSON, JSON.stringify({}, null, 2));
    if (!fs.existsSync(HIDDEN_JSON)) fs.writeFileSync(HIDDEN_JSON, JSON.stringify({}, null, 2));
    function loadGamesJSON() {
        try {
            return JSON.parse(fs.readFileSync(GAMES_JSON, "utf8"));
        } catch {
            return {};
        }
    }
    function saveGamesJSON(data) {
        fs.writeFileSync(GAMES_JSON, JSON.stringify(data, null, 2));
    }
    const upload = multer({
        storage: multer.memoryStorage(),
        limits: { fileSize: MAX_GAME_UPLOAD_BYTES, files: 2 },
    });
    const thumbOnlyUpload = multer({
        storage: multer.memoryStorage(),
        limits: { fileSize: MAX_THUMB_BYTES, files: 1 },
    });
    function dirForKind(kind) {
        return kind === "update" ? PENDING_UPDATES_DIR : PENDING_GAMES_DIR;
    }
    function readPendingInfo(kind, id) {
        const folder = path.join(dirForKind(kind), path.basename(id));
        if (!folder.startsWith(dirForKind(kind))) return null;
        const infoPath = path.join(folder, "info.json");
        if (!fs.existsSync(infoPath)) return null;
        try {
            return { folder, info: JSON.parse(fs.readFileSync(infoPath, "utf8")) };
        } catch {
            return null;
        }
    }
    app.post("/api/games/upload", verifyFirebaseToken, (req, res) => {
        upload.fields([{ name: "file", maxCount: 1 }, { name: "thumbnail", maxCount: 1 }])(req, res, async (err) => {
            if (err) {
                if (err instanceof multer.MulterError && err.code === "LIMIT_FILE_SIZE") {
                    return res.status(400).json({ ok: false, error: "File Exceeds The Allowed Size Limit" });
                }
                return res.status(400).json({ ok: false, error: err.message || "Upload Failed" });
            }
            try {
                const uid = req.user.uid;
                const file = (req.files && req.files.file && req.files.file[0]) || null;
                const thumbFile = (req.files && req.files.thumbnail && req.files.thumbnail[0]) || null;
                let { name, type, description, gameUrl } = req.body;
                name = (name || "").trim();
                description = (description || "").trim();
                type = (type || "").trim().toLowerCase();
                gameUrl = (gameUrl || "").trim();
                if (!name) return res.status(400).json({ ok: false, error: "Game Name Is Required" });
                if (name.length > MAX_NAME_LEN) return res.status(400).json({ ok: false, error: `Game Name Must Be ${MAX_NAME_LEN} Characters Or Fewer` });
                if (!["html5", "flash", "url"].includes(type)) return res.status(400).json({ ok: false, error: "Invalid Game Type" });
                if (description.length > MAX_DESC_LEN) return res.status(400).json({ ok: false, error: `Description Must Be ${MAX_DESC_LEN} Characters Or Fewer` });
                let validatedUrl = null;
                if (type === "url") {
                    try {
                        validatedUrl = validateGameUrl(gameUrl);
                    } catch (e) {
                        return res.status(400).json({ ok: false, error: e.message });
                    }
                    if (!thumbFile) return res.status(400).json({ ok: false, error: "A Thumbnail Is Required For URL Games" });
                } else {
                    if (!file) return res.status(400).json({ ok: false, error: "No File Provided" });
                    const ext = path.extname(file.originalname).toLowerCase();
                    if (ext !== EXT_BY_TYPE[type]) {
                        return res.status(400).json({ ok: false, error: `${type.toUpperCase()} Games Must Be Uploaded As ${EXT_BY_TYPE[type]} Files` });
                    }
                    const magic = detectMagic(file.buffer);
                    if (type === "flash" && magic !== "swf") return res.status(400).json({ ok: false, error: "File Does Not Look Like A Valid SWF" });
                    if (type === "html5" && magic !== "zip") return res.status(400).json({ ok: false, error: "File Does Not Look Like A Valid Zip Archive" });
                    if (type === "html5") {
                        try {
                            validateZipBuffer(file.buffer, { requireIndexHtml: true });
                        } catch (e) {
                            return res.status(400).json({ ok: false, error: e.message });
                        }
                    }
                }
                let thumbExt = null;
                if (thumbFile) {
                    try {
                        thumbExt = validateThumbnailBuffer(thumbFile.buffer);
                    } catch (e) {
                        return res.status(400).json({ ok: false, error: e.message });
                    }
                }
                const games = loadGamesJSON();
                let isUpdate = false;
                let targetGameId = null;
                let displayName = name;
                const updateMatch = name.match(/^Update:\s*(.+)\/([^/]+)$/i);
                if (updateMatch) {
                    isUpdate = true;
                    displayName = updateMatch[1].trim();
                    targetGameId = updateMatch[2].trim();
                    if (!games[targetGameId]) {
                        return res.status(400).json({ ok: false, error: "Game Not Found For Update" });
                    }
                }
                const kind = isUpdate ? "update" : "new";
                const parentDir = dirForKind(kind);
                const folderName = `${sanitizeFolderName(isUpdate ? `Update_${targetGameId}` : displayName, sanitize)}_${Date.now()}`;
                const folderPath = path.join(parentDir, folderName);
                fs.mkdirSync(folderPath, { recursive: true });
                let safeFileName = null;
                let fileSize = 0;
                if (type !== "url") {
                    safeFileName = `game${EXT_BY_TYPE[type]}`;
                    fs.writeFileSync(path.join(folderPath, safeFileName), file.buffer);
                    fileSize = file.buffer.length;
                }
                let thumbFileName = null;
                if (thumbFile) {
                    thumbFileName = `thumb${thumbExt}`;
                    fs.writeFileSync(path.join(folderPath, thumbFileName), thumbFile.buffer);
                }
                const info = {
                    name: displayName,
                    type,
                    filename: safeFileName,
                    thumbnail: thumbFileName,
                    url: type === "url" ? validatedUrl : null,
                    description,
                    uid,
                    uploadedAt: Date.now(),
                    isUpdate,
                    targetGameId,
                    size: fileSize,
                };
                fs.writeFileSync(path.join(folderPath, "info.json"), JSON.stringify(info, null, 2));
                res.json({ ok: true, id: folderName, kind });
                try {
                    const profile = readDataPath(`users/${uid}/profile`) || {};
                    if (!profile.gameUploader && typeof updateDataPath === "function") {
                        updateDataPath(`users/${uid}/profile`, { gameUploader: true });
                    }
                } catch (e) {
                    console.error("Failed To Set gameUploader Role:", e.message);
                }
                try {
                    const profile = readDataPath(`users/${uid}/profile`) || {};
                    const uploaderName = profile.displayName || "Unknown User";
                    const watchLink = "https://www.infinitecampus.xyz/InfiniteAdmins.html?games=true";
                    const embed = {
                        title: isUpdate ? "New Game Update Submitted" : "New Game Submitted",
                        description:
                            `Name: **${displayName}**\n` +
                            `Type: **${type.toUpperCase()}**\n` +
                            (type === "url" ? `URL: **${validatedUrl}**\n` : `Size: **${formatBytesLocal(fileSize)}**\n`) +
                            `Uploaded By: **${uploaderName}** (${uid})`,
                        color: 0x8cbe37,
                    };
                    await discordRequest({
                        method: "post",
                        url: `https://discord.com/api/v10/channels/${logid}/messages`,
                        data: {
                            embeds: [embed],
                            components: [
                                {
                                    type: 1,
                                    components: [{ type: 2, style: 5, label: "Review", url: watchLink }],
                                },
                            ],
                        },
                        headers: { "Content-Type": "application/json" },
                    });
                } catch (e) {
                    console.error("Failed To Send Game Discord Notification:", e.message);
                }
            } catch (e) {
                console.error("Game Upload Error:", e);
                res.status(500).json({ ok: false, error: "Server Error" });
            }
        });
    });
    app.get("/admin/games/pending", (req, res) => {
        try {
            const list = [];
            for (const kind of ["new", "update"]) {
                const dir = dirForKind(kind);
                for (const folder of fs.readdirSync(dir)) {
                    const infoPath = path.join(dir, folder, "info.json");
                    if (!fs.existsSync(infoPath)) continue;
                    try {
                        const info = JSON.parse(fs.readFileSync(infoPath, "utf8"));
                        const filePath = info.filename ? path.join(dir, folder, info.filename) : null;
                        const size = filePath && fs.existsSync(filePath) ? fs.statSync(filePath).size : info.size || 0;
                        list.push({
                            id: folder,
                            kind,
                            name: info.name,
                            type: info.type,
                            url: info.url || null,
                            hasThumbnail: !!info.thumbnail,
                            size,
                            humanSize: formatBytesLocal(size),
                            uid: info.uid,
                            uploadedAt: info.uploadedAt,
                            description: info.description,
                            isUpdate: info.isUpdate,
                            targetGameId: info.targetGameId,
                        });
                    } catch {}
                }
            }
            list.sort((a, b) => (a.uploadedAt || 0) - (b.uploadedAt || 0));
            res.json({ ok: true, games: list });
        } catch (e) {
            res.status(500).json({ ok: false, error: "Server Error" });
        }
    });
    app.get("/game_preview_x9a7b2/:kind/:id{/*rest}", (req, res) => {
        const kind = req.params.kind === "update" ? "update" : "new";
        const id = path.basename(req.params.id);
        const rest = Array.isArray(req.params.rest) ? req.params.rest.join("/") : (req.params.rest || "");
        const found = readPendingInfo(kind, id);
        if (!found) return res.status(404).send("Not Found");
        const { folder, info } = found;
        if (rest === "thumbnail") return serveThumbnail(res, folder, info.thumbnail);
        const basePath = `/game_preview_x9a7b2/${kind}/${encodeURIComponent(req.params.id)}/`;
        if (info.type === "url") {
            if (!info.url) return res.status(404).send("Not Found");
            return serveUrlGameAsset(res, info.url, rest, basePath);
        }
        const filePath = path.join(folder, info.filename);
        if (!fs.existsSync(filePath)) return res.status(404).send("Not Found");
        serveGameAsset(res, info.type, filePath, id + ":" + kind, rest, basePath);
    });
    app.post("/admin/games/accept", (req, res) => {
        try {
            const { id, kind } = req.body || {};
            const found = readPendingInfo(kind, id);
            if (!found) return res.status(404).json({ ok: false, error: "Not Found" });
            const { folder, info } = found;
            const games = loadGamesJSON();
            if (kind === "update") {
                const target = games[info.targetGameId];
                if (!target) return res.status(400).json({ ok: false, error: "Target Game No Longer Exists" });
                const targetFolder = path.join(GAMES_DIR, info.targetGameId);
                if (!fs.existsSync(targetFolder)) fs.mkdirSync(targetFolder, { recursive: true });
                if (info.type === "url") {
                    if (target.file) {
                        const oldFile = path.join(targetFolder, target.file);
                        if (fs.existsSync(oldFile)) fs.rmSync(oldFile, { force: true });
                    }
                    target.type = "url";
                    target.url = info.url;
                    target.file = null;
                } else {
                    const filePath = path.join(folder, info.filename);
                    const oldFile = target.file ? path.join(targetFolder, target.file) : null;
                    if (oldFile && fs.existsSync(oldFile) && target.file !== info.filename) {
                        fs.rmSync(oldFile, { force: true });
                    }
                    fs.copyFileSync(filePath, path.join(targetFolder, info.filename));
                    target.file = info.filename;
                    target.type = info.type;
                    target.url = null;
                }
                if (info.thumbnail) {
                    const oldThumb = target.thumbnail ? path.join(targetFolder, target.thumbnail) : null;
                    if (oldThumb && fs.existsSync(oldThumb) && target.thumbnail !== info.thumbnail) {
                        fs.rmSync(oldThumb, { force: true });
                    }
                    fs.copyFileSync(path.join(folder, info.thumbnail), path.join(targetFolder, info.thumbnail));
                    target.thumbnail = info.thumbnail;
                }
                if (info.description && info.description.trim() !== "") {
                    target.description = info.description;
                }
                target.dateUpdated = Date.now();
                games[info.targetGameId] = target;
                saveGamesJSON(games);
                zipCache.delete(info.targetGameId);
                fs.rmSync(folder, { recursive: true, force: true });
                return res.json({ ok: true, id: info.targetGameId });
            }
            const finalFolderName = uniqueFolderName(GAMES_DIR, info.name, sanitize);
            const finalFolder = path.join(GAMES_DIR, finalFolderName);
            fs.mkdirSync(finalFolder, { recursive: true });
            if (info.type !== "url") {
                fs.copyFileSync(path.join(folder, info.filename), path.join(finalFolder, info.filename));
            }
            if (info.thumbnail) {
                fs.copyFileSync(path.join(folder, info.thumbnail), path.join(finalFolder, info.thumbnail));
            }
            games[finalFolderName] = {
                name: info.name,
                file: info.type === "url" ? null : info.filename,
                type: info.type,
                url: info.type === "url" ? info.url : null,
                thumbnail: info.thumbnail || null,
                description: info.description || "",
                uploader: info.uid,
                popularity: 0,
                dateAdded: Date.now(),
            };
            saveGamesJSON(games);
            fs.rmSync(folder, { recursive: true, force: true });
            res.json({ ok: true, id: finalFolderName });
        } catch (e) {
            console.error("Game Accept Error:", e);
            res.status(500).json({ ok: false, error: "Server Error" });
        }
    });
    app.post("/admin/games/reject", (req, res) => {
        try {
            const { id, kind } = req.body || {};
            const found = readPendingInfo(kind, id);
            if (!found) return res.status(404).json({ ok: false, error: "Not Found" });
            fs.rmSync(found.folder, { recursive: true, force: true });
            res.json({ ok: true });
        } catch (e) {
            res.status(500).json({ ok: false, error: "Server Error" });
        }
    });
    app.get("/admin/games/list", (req, res) => {
        try {
            const games = loadGamesJSON();
            const list = Object.entries(games)
                .map(([id, g]) => ({ id, ...g }))
                .sort((a, b) => (b.dateAdded || 0) - (a.dateAdded || 0));
            res.json({ ok: true, games: list });
        } catch (e) {
            res.status(500).json({ ok: false, error: "Server Error" });
        }
    });
    app.post("/admin/games/patch", (req, res) => {
        try {
            const { id, patch } = req.body || {};
            const games = loadGamesJSON();
            if (!id || !games[id]) return res.status(404).json({ ok: false, error: "Not Found" });
            if (!patch || typeof patch !== "object") return res.status(400).json({ ok: false, error: "Invalid Patch" });
            const game = games[id];
            if (typeof patch.name === "string") {
                const trimmed = patch.name.trim();
                if (!trimmed) return res.status(400).json({ ok: false, error: "Name Cannot Be Empty" });
                if (trimmed.length > MAX_NAME_LEN) return res.status(400).json({ ok: false, error: `Name Must Be ${MAX_NAME_LEN} Characters Or Fewer` });
                game.name = trimmed;
            }
            if (typeof patch.description === "string") {
                if (patch.description.length > MAX_DESC_LEN) return res.status(400).json({ ok: false, error: `Description Must Be ${MAX_DESC_LEN} Characters Or Fewer` });
                game.description = patch.description;
            }
            if (typeof patch.url === "string" && game.type === "url") {
                try {
                    game.url = validateGameUrl(patch.url);
                } catch (e) {
                    return res.status(400).json({ ok: false, error: e.message });
                }
            }
            games[id] = game;
            saveGamesJSON(games);
            res.json({ ok: true, game: { id, ...game } });
        } catch (e) {
            res.status(500).json({ ok: false, error: "Server Error" });
        }
    });
    app.post("/admin/games/edit-raw", (req, res) => {
        try {
            const { id, data } = req.body || {};
            const games = loadGamesJSON();
            if (!id || !games[id]) return res.status(404).json({ ok: false, error: "Not Found" });
            if (!data || typeof data !== "object" || Array.isArray(data)) {
                return res.status(400).json({ ok: false, error: "Invalid Game Data" });
            }
            if (!data.name || typeof data.name !== "string") return res.status(400).json({ ok: false, error: "Game Must Have A Name" });
            if (!["html5", "flash", "url"].includes(data.type)) return res.status(400).json({ ok: false, error: "Invalid Game Type" });
            if (data.type === "url") {
                try {
                    data.url = validateGameUrl(data.url);
                } catch (e) {
                    return res.status(400).json({ ok: false, error: e.message });
                }
            }
            const existing = games[id];
            const merged = {
                ...data,
                file: existing.file ?? null,
                thumbnail: existing.thumbnail ?? null,
            };
            games[id] = merged;
            saveGamesJSON(games);
            zipCache.delete(id);
            res.json({ ok: true, game: { id, ...merged } });
        } catch (e) {
            res.status(500).json({ ok: false, error: "Server Error" });
        }
    });
    app.post("/admin/games/delete", (req, res) => {
        try {
            const { id } = req.body || {};
            const games = loadGamesJSON();
            if (!id || !games[id]) return res.status(404).json({ ok: false, error: "Not Found" });
            delete games[id];
            saveGamesJSON(games);
            zipCache.delete(id);
            const folder = path.join(GAMES_DIR, id);
            if (fs.existsSync(folder)) fs.rmSync(folder, { recursive: true, force: true });
            res.json({ ok: true });
        } catch (e) {
            res.status(500).json({ ok: false, error: "Server Error" });
        }
    });
    app.post("/admin/games/thumbnail", (req, res) => {
        thumbOnlyUpload.single("thumbnail")(req, res, (err) => {
            if (err) {
                if (err instanceof multer.MulterError && err.code === "LIMIT_FILE_SIZE") {
                    return res.status(400).json({ ok: false, error: "Thumbnail Exceeds The 5MB Limit" });
                }
                return res.status(400).json({ ok: false, error: err.message || "Upload Failed" });
            }
            try {
                const { id } = req.body || {};
                const games = loadGamesJSON();
                if (!id || !games[id]) return res.status(404).json({ ok: false, error: "Not Found" });
                if (!req.file) return res.status(400).json({ ok: false, error: "No Thumbnail Provided" });
                let ext;
                try {
                    ext = validateThumbnailBuffer(req.file.buffer);
                } catch (e) {
                    return res.status(400).json({ ok: false, error: e.message });
                }
                const game = games[id];
                const folder = path.join(GAMES_DIR, id);
                if (!fs.existsSync(folder)) fs.mkdirSync(folder, { recursive: true });
                if (game.thumbnail) {
                    const oldPath = path.join(folder, game.thumbnail);
                    if (fs.existsSync(oldPath)) fs.rmSync(oldPath, { force: true });
                }
                const thumbFileName = `thumb${ext}`;
                fs.writeFileSync(path.join(folder, thumbFileName), req.file.buffer);
                game.thumbnail = thumbFileName;
                games[id] = game;
                saveGamesJSON(games);
                res.json({ ok: true, thumbnail: thumbFileName });
            } catch (e) {
                res.status(500).json({ ok: false, error: "Server Error" });
            }
        });
    });
    app.get("/api/games-json", (req, res) => {
        try {
            res.json(loadGamesJSON());
        } catch {
            res.status(500).json({ error: "Failed To Load games.json" });
        }
    });
    const popularityDebounce = new Map();
    app.post("/api/games/:id/popularity", (req, res) => {
        try {
            const id = req.params.id;
            const games = loadGamesJSON();
            if (!games[id]) return res.status(404).json({ ok: false, error: "Not Found" });
            const ip = req.headers["x-forwarded-for"]?.split(",")[0] || req.socket?.remoteAddress || "unknown";
            const key = `${ip}:${id}`;
            const now = Date.now();
            const last = popularityDebounce.get(key) || 0;
            if (now - last > 10_000) {
                games[id].popularity = (games[id].popularity || 0) + 1;
                saveGamesJSON(games);
                popularityDebounce.set(key, now);
            }
            res.json({ ok: true, popularity: games[id].popularity });
        } catch {
            res.status(500).json({ ok: false });
        }
    });
    app.get("/api/games/by-user/:uid", async (req, res) => {
        try {
            const targetUid = req.params.uid;
            let viewerUid = null;
            const header = req.headers.authorization || "";
            const token = header.split("Bearer ")[1];
            if (token) {
                try {
                    const decoded = await deps.admin?.auth().verifyIdToken(token);
                    viewerUid = decoded?.uid || null;
                } catch {}
            }
            const isOwnProfile = viewerUid && viewerUid === targetUid;
            const games = loadGamesJSON();
            const accepted = Object.entries(games)
                .filter(([, g]) => g.uploader === targetUid)
                .map(([id, g]) => ({
                    id,
                    name: g.name,
                    type: g.type,
                    hasThumbnail: !!g.thumbnail,
                    popularity: g.popularity || 0,
                    dateAdded: g.dateAdded,
                    pending: false,
                }));
            let pending = [];
            if (isOwnProfile) {
                for (const kind of ["new", "update"]) {
                    const dir = dirForKind(kind);
                    for (const folder of fs.readdirSync(dir)) {
                        const infoPath = path.join(dir, folder, "info.json");
                        if (!fs.existsSync(infoPath)) continue;
                        try {
                            const info = JSON.parse(fs.readFileSync(infoPath, "utf8"));
                            if (info.uid !== targetUid) continue;
                            pending.push({
                                id: folder,
                                name: info.name,
                                type: info.type,
                                hasThumbnail: !!info.thumbnail,
                                popularity: 0,
                                dateAdded: info.uploadedAt,
                                pending: true,
                            });
                        } catch {}
                    }
                }
            }
            res.json({ ok: true, games: [...accepted, ...pending].sort((a, b) => (b.dateAdded || 0) - (a.dateAdded || 0)) });
        } catch (e) {
            res.status(500).json({ ok: false, error: "Server Error" });
        }
    });
    app.get("/gamefiles/:id{/*rest}", (req, res) => {
        const id = req.params.id;
        const rest = Array.isArray(req.params.rest) ? req.params.rest.join("/") : (req.params.rest || "");
        const games = loadGamesJSON();
        const g = games[id];
        if (!g) return res.status(404).send("Not Found");
        if (rest === "thumbnail") return serveThumbnail(res, path.join(GAMES_DIR, id), g.thumbnail);
        const basePath = `/gamefiles/${encodeURIComponent(id)}/`;
        if (g.type === "url") {
            if (!g.url) return res.status(404).send("Not Found");
            return serveUrlGameAsset(res, g.url, rest, basePath);
        }
        const filePath = path.join(GAMES_DIR, id, g.file);
        if (!fs.existsSync(filePath)) return res.status(404).send("Not Found");
        serveGameAsset(res, g.type, filePath, id, rest, basePath);
    });
}
export function attachGameAssetFallback(app, deps) {
    const { __dirname } = deps;
    const GAMES_DIR = path.join(__dirname, "games");
    const PENDING_GAMES_DIR = path.join(__dirname, "pendinggames");
    const PENDING_UPDATES_DIR = path.join(__dirname, "pendingupdates");
    const GAMES_JSON = path.join(__dirname, "data", "games", "games.json");
    function loadGamesJSON() {
        try {
            return JSON.parse(fs.readFileSync(GAMES_JSON, "utf8"));
        } catch {
            return {};
        }
    }
    app.use((req, res, next) => {
        if (req.method !== "GET" && req.method !== "HEAD") return next();
        if (req.path.startsWith("/gamefiles/") || req.path.startsWith("/game_preview_x9a7b2/")) return next();
        const referer = req.headers.referer || req.headers.referrer;
        if (!referer) return next();
        let refPath;
        try {
            refPath = new URL(referer).pathname;
        } catch {
            return next();
        }
        const liveMatch = refPath.match(/^\/gamefiles\/([^/]+)\/?/);
        const previewMatch = !liveMatch && refPath.match(/^\/game_preview_x9a7b2\/(new|update)\/([^/]+)\/?/);
        if (!liveMatch && !previewMatch) return next();
        const rest = req.path.replace(/^\/+/, "");
        if (liveMatch) {
            let id;
            try {
                id = decodeURIComponent(liveMatch[1]);
            } catch {
                return next();
            }
            const games = loadGamesJSON();
            const g = games[id];
            if (!g) return next();
            const basePath = `/gamefiles/${liveMatch[1]}/`;
            if (g.type === "html5") {
                const filePath = path.join(GAMES_DIR, id, g.file);
                if (!fs.existsSync(filePath)) return next();
                return serveGameAsset(res, g.type, filePath, id, rest, basePath);
            }
            if (g.type === "url" && g.url) {
                return serveUrlGameAsset(res, g.url, rest, basePath, true);
            }
            return next();
        }
        const kind = previewMatch[1];
        let id;
        try {
            id = decodeURIComponent(previewMatch[2]);
        } catch {
            return next();
        }
        const folder = path.join(kind === "update" ? PENDING_UPDATES_DIR : PENDING_GAMES_DIR, path.basename(id));
        const infoPath = path.join(folder, "info.json");
        if (!fs.existsSync(infoPath)) return next();
        let info;
        try {
            info = JSON.parse(fs.readFileSync(infoPath, "utf8"));
        } catch {
            return next();
        }
        const basePath = `/game_preview_x9a7b2/${kind}/${previewMatch[2]}/`;
        if (info.type === "html5") {
            const filePath = path.join(folder, info.filename);
            if (!fs.existsSync(filePath)) return next();
            return serveGameAsset(res, info.type, filePath, id + ":" + kind, rest, basePath);
        }
        if (info.type === "url" && info.url) {
            return serveUrlGameAsset(res, info.url, rest, basePath, true);
        }
        return next();
    });
}