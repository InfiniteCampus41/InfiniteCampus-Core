import admin from "firebase-admin";
import axios from "axios";
import child_process from "child_process";
import { Client, Environment, WebhooksHelper } from "square";
import cors from "cors";
import { createServer } from "http";
import crypto from "crypto";
import dotenv from "dotenv";
import express from "express";
import { fileURLToPath } from "url";
import FormData from "form-data";
import fs from "fs";
import https from "https";
import multer from "multer";
import os from "os";
import path from "path";
import readline from "readline";
import sanitize from "sanitize-filename";
import { Server as IOServer } from "socket.io";
import { spawn } from "child_process";
import util from "util";
import { WebSocketServer } from "ws";
import fetch from "node-fetch";
import { renderTemplate, formatExpire, getPremiumTierLabel } from "./emailTemplates.js";
import { Resend } from "resend";
dotenv.config();
const app = express();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const UPLOADS_TEMP_DIR = path.join(__dirname, "uploads_temp");
const UPLOADS_DIR = path.join(__dirname, "uploads");
const UNIQUE_SUFFIX = "x9a7b2";
const UPLOAD_LIMIT_MB = 100;
const DISCORD_IDS_PATH = path.join(__dirname, "discordids.json");
const acceptIntervals = new Map();
const acceptStatus = new Map();
const ACCLOGS_PATH = path.join(__dirname, "acclogs.json");
let activeLinks = [];
const ALLOWED_EXTS = new Set([".mp4", ".mov", ".mkv", ".ts", ".webm", ".avi", ".flv", ".mpeg", ".mpg", ".m4v",]);
const ALLOWED_PFP_EXTS = new Set([".png", ".jpeg", ".jpg", ".webp", ".ico"]);
let alreadyArchived = false;
let alreadyCleared = false;
const anonSessions = new Map();
const ANON_SESSION_TTL = 24 * 60 * 60 * 1000;
const applicantMessages = new Map();
const APPLY_DIR = path.join(__dirname, "apply");
const APPLY_JSON = path.join(__dirname, "apply.json");
const ARCHIVE_DIR = path.join(__dirname, "archive");
const AUTO_DELETE_MS = 5 * 60 * 1000;
const AUTO_DELETE_PM_MS = 15 * 60 * 1000;
const botSentDiscordIds = loadBotSentDiscordIds();
const client = new Client({
    environment: Environment.Production,
    accessToken: process.env.SQUARE_ACCESS_TOKEN,
});
const CREATE_COOLDOWN = 1500;
const creating = new Map();
let _dataCache = null;
let _dataCacheDirty = false;
const DATA_PATH = path.join(__dirname, "data.json");
const DEFAULT_CHANNEL_ID = process.env.CHANNEL_ID;
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const discordBridgeState = {};
const DISCORD_CHANNEL_MAP_PATH = path.join(__dirname, "discord_channel_map.json");
let DISCORD_CHANNEL_MAP = (() => {
    try {
        if (fs.existsSync(DISCORD_CHANNEL_MAP_PATH)) {
            return JSON.parse(fs.readFileSync(DISCORD_CHANNEL_MAP_PATH, "utf-8"));
        }
    } catch (e) { console.warn("Failed To Load Channel Map:", e.message); }
    try {
        return JSON.parse(process.env.DISCORD_CHANNEL_MAP || "{}");
    } catch { return {}; }
})();
let DISCORD_DISABLED = false;
let discordGatewayActive = null;
let discordGatewayWs = null;
let discordMessageListenerAttached = false;
const discordMsgIdToTimestamp = {};
const discordQueue = [];
const DISCORD_QUEUE_DIR = path.join(__dirname, "discord_queue");
let discordQueueProcessing = false;
const DISCORD_QUEUE_TTL = 5 * 60 * 1000;
const DISCORD_RPS = 48;
const discordVerifications = new Map();
const diskStorage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOADS_DIR),
    filename: (req, file, cb) => {
        const uniqueName = Date.now() + "-" + file.originalname.replace(/\s+/g, "_");
        cb(null, uniqueName);
    },
});
const diskUpload = multer({ storage: diskStorage, limits: { fileSize: UPLOAD_LIMIT_MB * 1024 * 1024 } });
const donationSessions = new Map();
const exec = util.promisify(util.promisify ? util.promisify : (fn => fn));
const execProm = util.promisify(child_process.exec);
const FOLDER_LIMIT_MB = 1024;
const GATEWAY_BASE_RECONNECT_DELAY = 3000;
let gatewayCanResume = false;
let gatewayHeartbeatInterval = null;
const GATEWAY_MAX_RECONNECT_ATTEMPTS = 10;
const GATEWAY_MAX_RECONNECT_DELAY = 5 * 60 * 1000;
let gatewayReconnectAttempts = 0;
let gatewayReconnectTimer = null;
let gatewayResumeUrl = null;
let gatewaySessionId = null;
let gatewaySeq = null;
const httpServer = createServer(app);
const ioLive = new IOServer(httpServer, {
    path: "/socket_io_live_" + UNIQUE_SUFFIX,
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});
const ioRealtime = new IOServer(httpServer, {
    path: "/socket_io_realtime_" + UNIQUE_SUFFIX,
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});
let lastCreateTime = 0;
let _listFilesInterval = null;
let liveInterval = null;
let liveMode = false;
let LOCKDOWN = false;
const logid = "1460410323369721868";
const MAX_APPLY_BYTES = 30 * 1024 * 1024 * 1024;
const MAX_DISCORD_QUEUE = 5000;
const MAX_FILE_BYTES = 1024 * 1024 * 1024 * 30;
const MAX_REACTIONS_PER_MSG = 5;
const MAX_REACTIONS_PER_USER_MSG = 20;
const MAX_SIZE_NON_PREMIUM = 100 * 1024 * 1024;
const MAX_SIZE_PREMIUM = 500 * 1024 * 1024;
let memoryUpload = multer({
    storage: multer.diskStorage({
        destination: UPLOADS_TEMP_DIR,
        filename: (req,file,cb)=>cb(null,Date.now()+"-"+file.originalname)
    })
});
const MOVIES_DIR = path.join(__dirname, "movies");
const MOVIES_JSON = path.join(__dirname, "movies.json");
const MSG_SLOWMODE_MS = 3000;
const _msgSlowmodeStore = new Map();
const onlineLastSeen = new Map();
const PFP_COOLDOWN_MS = 3 * 60 * 1000;
const pfpStorage = multer.memoryStorage();
const pfpUploadCooldown = new Map();
const pinnedAcceptLines = new Map();
const PORT = process.env.PORT || 4000;
const PREMIUM_NOTICE_SENT_KEY = "premiumNoticeSent";
const QUEUE_DIR = path.join(__dirname, "queue");
const RATE_LIMIT_ENABLED = true;
const rateLimitLogs = [];
const RATE_LIMITS = {
    read:    { max: 500,  window: 10_000 },  // 500 reads  / 10 s
    write:   { max: 25,  window: 10_000 },  // 25 writes / 10 s
    delete:  { max: 15,  window: 10_000 },  // 15 deletes/ 10 s
    react:   { max: 20,  window: 10_000 },  // 20 reacts / 10 s
    online:  { max: 20,   window: 30_000 },  // 20  pings  / 30 s  (client calls every 20 s)
    upload:  { max: 10,  window: 60_000 },  // 10 uploads/ 60 s
    default: { max: 40,  window: 10_000 },
};
const _rateLimitStore = new Map();
const READY_DIR = path.join(__dirname, "ready");
const REPORT_JSON = path.join(__dirname, "report.json");
const resend = new Resend(process.env.RESEND_API_KEY);
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const ROUTES = {
    UPLOAD: `/api/upload_apply_${UNIQUE_SUFFIX}`,
    LIST_APPLY: `/api/list_apply_${UNIQUE_SUFFIX}`,
    STREAM_APPLY: `/apply_stream_${UNIQUE_SUFFIX}/:name`,
    LIST_VIDEOS: `/api/list_videos_${UNIQUE_SUFFIX}`,
    STREAM_VIDEO: `/movies/${UNIQUE_SUFFIX}/:name`,
    DOWNLOAD_VIDEO: `/download/${UNIQUE_SUFFIX}/:name`,
    DELETE_VIDEO: `/delete/${UNIQUE_SUFFIX}/:name`,
    ADMIN_ACCEPT: `/admin/accept_${UNIQUE_SUFFIX}`,
};
const RULES_PATH = path.join(__dirname, "rules.json");
const SC_SEARCH_BASE = process.env.MUSIC_SEARCH_URL;
const SC_PLAY_URL = (u, t) => process.env.MUSIC_PLAY_URL;
const SC_DOWNLOAD_URL = (u, t) => process.env.MUSIC_DOWNLOAD_URL;
const seenUsers = new Set();
const server = httpServer.listen(PORT, () => {
    console.log(`Infinite Campus Server Running At http://localhost:${PORT}`);
    httpServer.setTimeout(0);
    httpServer.keepAliveTimeout = 0;
    httpServer.headersTimeout = 0;
    mainMenu();
});
const sessions = new Map();
const SQUARE_SIGNATURE_KEY = process.env.SQUARE_WEBHOOK_SIGNATURE_KEY;
const SQUARE_WEBHOOK_URL = process.env.SQUARE_WEBHOOK_URL;
const STALE_CLEANUP_DIRS = [
    UPLOADS_TEMP_DIR,
    path.join(UPLOADS_DIR, "tmp")
];
const STALE_CLEANUP_MS = 3 * 60 * 60 * 1000;
const storageApply = multer.diskStorage({
    destination: (req, file, cb) => cb(null, APPLY_DIR),
    filename: (req, file, cb) => cb(null, safeName(file.originalname)),
});
const tempUploadActivity = new Map();
const TEMP_UPLOAD_TIMEOUT = 3 * 60 * 60 * 1000;
let testEnabled = false;
const TMDB_API_KEY = process.env.TMDB_API_KEY;
const uploadApply = multer({
    storage: storageApply,
    limits: { fileSize: MAX_FILE_BYTES },
    fileFilter: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        if (!ALLOWED_EXTS.has(ext)) {
            return cb(new Error("Invalid File Type. Allowed: " + Array.from(ALLOWED_EXTS).join(", ")));
        }
        const current = folderSizeBytes(APPLY_DIR);
        if (current >= MAX_APPLY_BYTES) {
            return cb(new Error("Capacity Reached (30 GB). Please Wait For Movies To Be Accepted Before Applying"));
        }
        cb(null, true);
    },
}).single("file");
const uploadChunk = multer({ storage: multer.memoryStorage() });
const uploadLogs = [];
const uploadPfp = multer({
    storage: pfpStorage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        if (!ALLOWED_PFP_EXTS.has(ext)) {
            return cb(new Error("Invalid File Type"));
        }
        cb(null, true);
    }
});
const uploadProgress = new Map();
let vm;
const wsClients = new Map();
const WS_POLL_INTERVAL_NORMAL = 3000;
const WS_POLL_INTERVAL_TYPING = 1000;
const wss = new WebSocketServer({ noServer: true });
class DataSnapshot {
    constructor(data) {
        this.data = data;
    }
    child(path) {
        const keys = path.split("/");
        let current = this.data;
        for (const key of keys) {
            if (current == null) return new DataSnapshot(undefined);
            current = current[key];
        }
        return new DataSnapshot(current);
    }
    val() {
        return this.data;
    }
    exists() {
        return this.data !== undefined && this.data !== null;
    }
    isNumber() {
        return typeof this.data === "number";
    }
    isString() {
        return typeof this.data === "string";
    }
}
if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert(JSON.parse(fs.readFileSync("./admin.json"))),
        databaseURL: "https://notes-27f22-default-rtdb.firebaseio.com"
    });
}
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
if (!fs.existsSync(APPLY_DIR)) fs.mkdirSync(APPLY_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_TEMP_DIR)) fs.mkdirSync(UPLOADS_TEMP_DIR, { recursive: true });
if (!fs.existsSync(MOVIES_DIR)) fs.mkdirSync(MOVIES_DIR, { recursive: true });
if (!fs.existsSync(READY_DIR)) fs.mkdirSync(READY_DIR, { recursive: true });
if (!fs.existsSync(QUEUE_DIR)) fs.mkdirSync(QUEUE_DIR, { recursive: true });
if (!fs.existsSync(DISCORD_QUEUE_DIR)) fs.mkdirSync(DISCORD_QUEUE_DIR, { recursive: true });
if (!fs.existsSync(ARCHIVE_DIR)) fs.mkdirSync(ARCHIVE_DIR, { recursive: true });
if (!fs.existsSync(ACCLOGS_PATH)) {
    fs.writeFileSync(ACCLOGS_PATH, JSON.stringify({}), "utf8");
}
app.use((req, res, next) => {
    res.header(
        "Access-Control-Allow-Origin", 
        "*"
    );
    res.header(
        "Access-Control-Allow-Methods", 
        "GET, POST, PUT, DELETE, OPTIONS, PATCH"
    );
    res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, uploadedby, ngrok-skip-browser-warning, x-admin-password, fileId, chunkIndex, totalChunks, filename, x-user-id, X-File-Id, X-Chunk-Number, X-Total-Chunks, X-Filename, X-User-Id, X-Anon-Session");
    if (req.method === "OPTIONS") return res.sendStatus(200);
    next();
});
app.use(cors({ 
    origin: "*",
    methods: [
        "GET", 
        "POST", 
        "PUT", 
        "DELETE", 
        "OPTIONS", 
        "PATCH"
    ], 
    allowedHeaders: [ 
        "Content-Type", 
        "Authorization", 
        "uploadedby",
        "ngrok-skip-browser-warning", 
        "x-admin-password", 
        "fileId", 
        "chunkIndex", 
        "totalChunks", 
        "filename", 
        "x-user-id", 
        "X-File-Id", 
        "X-Chunk-Number", 
        "X-Total-Chunks", 
        "X-Filename",
        "X-User-Id",
        "X-Anon-Session"
    ]
}));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(express.static(path.join(__dirname, "public")));
app.use(requireAdminPassword);
app.use("/files", (req, res, next) => {
    const downloadQuery = req.query.download;
    if (downloadQuery) {
        const filePath = path.join(UPLOADS_DIR, req.path);
        if (fs.existsSync(filePath)) return res.download(filePath);
        else return res.status(404).send("File Not Found");
    }
    next();
});
app.all("/admin/modify-data", verifyFirebaseToken, async (req, res) => {
    try {
        const uid = req.user.uid;
        const profile = readDataPath(`users/${uid}/profile`);
        if (!profile || !profile.isOwner) {
            return res.status(403).json({ error: "Not Authorized: Owner Only" });
        }
        if (req.method === "GET") {
            if (!fs.existsSync(DATA_PATH)) {
                return res.status(404).json({ error: "data.json Not Found" });
            }
            const raw = fs.readFileSync(DATA_PATH, "utf8");
            return res.json({ data: JSON.parse(raw) });
        }
        if (req.method === "POST") {
            const { data } = req.body;
            if (!data || typeof data !== "object") {
                return res.status(400).json({ error: "Missing Or Invalid Data Object" });
            }
            saveData(data);
            console.log(`[admin/modify-data] data.json Overwritten By Owner ${uid}`);
            return res.json({ ok: true });
        }
        if (req.method === "PATCH") {
            const { patches } = req.body;
            if (!Array.isArray(patches) || patches.length === 0) {
                return res.status(400).json({ error: "Missing Or Invalid Patches Array" });
            }
            const data = getDataCache();
            for (const { path: patchPath, value } of patches) {
                if (typeof patchPath !== "string") continue;
                const keys = patchPath.split("/").filter(Boolean);
                if (keys.length === 0) continue;
                let cur = data;
                for (let i = 0; i < keys.length - 1; i++) {
                    if (!cur[keys[i]] || typeof cur[keys[i]] !== "object") cur[keys[i]] = {};
                    cur = cur[keys[i]];
                }
                const last = keys[keys.length - 1];
                if (value === null || value === undefined) {
                    delete cur[last];
                } else {
                    cur[last] = value;
                }
            }
            saveData(data);
            console.log(`[admin/modify-data PATCH] ${patches.length} patch(es) applied by ${uid}`);
            return res.json({ ok: true, patches: patches.length });
        }
        return res.status(405).json({ error: "Method Not Allowed" });
    } catch (err) {
        console.error("modify-data error:", err);
        return res.status(500).json({ error: err.message || "Internal Server Error" });
    }
});
app.all("/admin/modify-rules", verifyFirebaseToken, async (req, res) => {
    try {
        const uid = req.user.uid;
        const profile = readDataPath(`users/${uid}/profile`);
        if (!profile || !(profile.isOwner || profile.isCoOwner || profile.isHAdmin || profile.isDev)) {
            return res.status(403).json({ error: "Not Authorized" });
        }
        if (req.method === "GET") {
            if (!fs.existsSync(RULES_PATH)) {
                return res.status(404).json({ error: "rules.json Not Found" });
            }
            const raw = fs.readFileSync(RULES_PATH, "utf8");
            return res.json({ rules: JSON.parse(raw) });
        }
        if (req.method === "POST") {
            const { rules } = req.body;
            if (!rules || typeof rules !== "object") {
                return res.status(400).json({ error: "Missing or invalid rules object" });
            }
            const newContent = JSON.stringify(rules, null, 2);
            fs.writeFileSync(RULES_PATH, newContent, "utf8");
            const report = loadReportJSON();
            const day = new Date().getDate().toString();
            if (!report.report[day]) report.report[day] = {};
            if (!report.report[day]["rules-modified"]) report.report[day]["rules-modified"] = { count: 0 };
            report.report[day]["rules-modified"].count++;
            if (!report.timesRulesModified) report.timesRulesModified = 0;
            report.timesRulesModified++;
            saveReportJSON(report);
            return res.json({ ok: true, timesRulesModified: report.timesRulesModified });
        }
        return res.status(405).json({ error: "Method Not Allowed" });
    } catch (err) {
        console.error("modify-rules error:", err);
        return res.status(500).json({ error: err.message || "Internal Server Error" });
    }
});
app.delete("/admin/files/:filename", (req, res) => {
    const pass = req.headers["x-admin-password"];
    if (pass === process.env.DON_PASS_1) {
        return res.status(403).json({
            error: "You Are Not Allowed To Use These Services"
        });
    }
    const filename = req.params.filename;
    const filePath = path.join(UPLOADS_DIR, filename);
    if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        return res.json({ success: true });
    }
    res.status(404).json({ error: "File Not Found" });
});
app.delete(ROUTES.DELETE_VIDEO, (req, res) => {
    const name = path.basename(req.params.name);
    const file = path.join(MOVIES_DIR, name + ".mp4");
    if (!fs.existsSync(file)) return res.status(404).send("Not Found");
    fs.unlinkSync(file);
    res.json({ ok: true });
});
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});
app.get("/admin/files", (req, res) => {
    const pass = req.headers["x-admin-password"];
    if (pass === process.env.DON_PASS_1) {
        return res.status(403).json({
            error: "You Are Not Allowed To Use These Services"
        });
    }
    const files = fs.readdirSync(UPLOADS_DIR).filter((f) => {
        try {
            return fs.statSync(path.join(UPLOADS_DIR, f)).isFile();
        } catch {
            return false;
        }
    });
    const fileData = files
    .map((file, i) => {
        let stats;
        try {
            stats = fs.statSync(path.join(UPLOADS_DIR, file));
        } catch {
            return;
        }
        const ageMs = Date.now() - stats.birthtimeMs;
        return {
            number: i + 1,
            name: file,
            size: stats.size,
            ageSec: Math.floor(ageMs / 1000),
            remainingSec: Math.max(0, Math.floor((AUTO_DELETE_MS - ageMs) / 1000)),
        };
    })
    .filter(Boolean);
    res.json(fileData);
});
app.get("/admin/logs", (req, res) => {
    const pass = req.headers["x-admin-password"];
    if (pass === process.env.DON_PASS_1) {
        return res.status(403).json({
            error: "You Are Not Allowed To Use The Log Services"
        });
    }
    res.json({
        uploadLogs: uploadLogs.slice(-100),
        rateLimitLogs: rateLimitLogs.slice(-100),
        activeLinks: activeLinks.slice(-100),
    });
});
app.get("/api/guest-channel-info", async (req, res) => {
    const channel = req.query.channel;
    if (!channel) return res.status(400).json({ error: "Missing channel" });
    const data = getDataCache();
    const chData = data?.channels?.[channel];
    if (!chData) return res.json({ guestRead: false, guestWrite: false });
    res.json({
        guestRead: !!(chData.guestRead),
        guestWrite: !!(chData.guestWrite),
    });
});
app.get("/api/movies-json", (req, res) => {
    const pass = req.headers["x-admin-password"];
    if (pass === process.env.DON_PASS_1) {
        return res.status(403).json({
            error: "You Are Not Allowed To Use These Services"
        });
    }
    try {
        const data = loadMoviesJSON();
        res.json(data);
    } catch (err) {
        res.status(500).json({ error: "Failed To Load movies.json" });
    }
});
app.get("/discord-avatar-proxy", async (req, res) => {
    const { url } = req.query;
    if (!url || !url.startsWith("https://cdn.discordapp.com/")) {
        return res.status(400).send("Bad URL");
    }
    try {
        const r = await fetch(url);
        if (!r.ok) return res.status(r.status).send("Upstream error");
        const ct = r.headers.get("content-type") || "image/png";
        res.setHeader("Content-Type", ct);
        r.body.pipe(res);
    } catch (e) {
        res.status(500).send("Proxy Error");
    }
});
app.get("/discord-channel-map", verifyFirebaseToken, async (req, res) => {
    try {
        const uid = req.user.uid;
        const profile = readDataPath(`users/${uid}/profile`);
        if (!profile || !(profile.isOwner || profile.isCoOwner || profile.isTester)) {
            return res.status(403).json({ error: "Not Authorized" });
        }
        res.json({ map: DISCORD_CHANNEL_MAP });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
app.get("/discord-media-proxy", async (req, res) => {
    const { url } = req.query;
    if (!url) return res.status(400).send("Bad URL");
    let parsed;
    try { parsed = new URL(url); } catch { return res.status(400).send("Invalid URL"); }
    try {
        const r = await fetch(url, { headers: { "User-Agent": "Mozilla/5.0" } });
        if (!r.ok) return res.status(r.status).send("Upstream error");
        const ct = r.headers.get("content-type") || "application/octet-stream";
        const cl = r.headers.get("content-length");
        res.setHeader("Content-Type", ct);
        res.setHeader("Cache-Control", "public, max-age=3600");
        if (cl) res.setHeader("Content-Length", cl);
        r.body.pipe(res);
    } catch (e) {
        res.status(500).send("Proxy error: " + e.message);
    }
});
app.get("/files/:filename", (req, res) => {
    const fileName = req.params.filename;
    const filePath = path.join(UPLOADS_DIR, fileName);
    if (!fs.existsSync(filePath)) return res.status(404).send("File Not Found");
    res.setHeader("Content-Disposition", `attachment; filename="${fileName}"`);
    res.setHeader("Content-Type", "application/octet-stream");
    fs.createReadStream(filePath).pipe(res);
});
app.get("/hyperadminvm", async (req, res) => {
    const uid = req.query.uid;
    if (!uid) {
        return res.status(400).send("Missing uid");
    }
    try {
        let session = sessions.get("admin_" + uid);
        if (session) {
            session.lastActive = Date.now();
            return res.json(session.vm);
        }
        if (creating.has("admin_" + uid)) {
            const vm = await creating.get("admin_" + uid);
            return res.json(vm);
        }
        const createPromise = createVM(process.env.HB_API_TEST_KEY);
        creating.set("admin_" + uid, createPromise);
        const vm = await createPromise;
        creating.delete("admin_" + uid);
        session = {
            vm,
            lastActive: Date.now(),
            timer: null
        };
        sessions.set("admin_" + uid, session);
        session.timer = setTimeout(async () => {
            try {
                await axios.delete(
                    `https://engine.hyperbeam.com/v0/vm/${vm.session_id}`,
                    {
                        headers: {
                            Authorization: `Bearer ${process.env.HB_API_TEST_KEY}`,
                        },
                    }
                );
                console.log(`Deleted ADMIN VM for ${uid}`);
            } catch (e) {
                console.error("Delete failed:", e.message);
            }
            sessions.delete("admin_" + uid);
        }, 30 * 60 * 1000);
        console.log("Created ADMIN VM for:", uid);
        res.json(vm);
    } catch (err) {
        creating.delete("admin_" + uid);
        console.error(err.response?.data || err.message);
        res.status(500).send("Failed to create admin VM");
    }
});
app.get("/hypervm", async (req, res) => {
    const uid = req.query.uid;
    if (!uid) {
        return res.status(400).send("Missing uid");
    }
    try {
        let session = sessions.get(uid);
        if (session) {
            session.lastActive = Date.now();
            return res.json(session.vm);
        }
        if (creating.has(uid)) {
            const vm = await creating.get(uid);
            return res.json(vm);
        }
        const createPromise = createVM(process.env.HB_API_KEY);
        creating.set(uid, createPromise);
        const vm = await createPromise;
        creating.delete(uid);
        session = {
            vm,
            lastActive: Date.now(),
            timer: null
        };
        sessions.set(uid, session);
        session.timer = setTimeout(async () => {
            try {
                await axios.delete(
                    `https://engine.hyperbeam.com/v0/vm/${vm.session_id}`,
                    {
                        headers: {
                            Authorization: `Bearer ${process.env.HB_API_KEY}`,
                        },
                    }
                );
                console.log(`Deleted VM for ${uid}`);
            } catch (e) {
                console.error("Delete failed:", e.message);
            }
            sessions.delete(uid);
        }, 30 * 60 * 1000);
        console.log("Created VM for:", uid);
        res.json(vm);
    } catch (err) {
        creating.delete(uid);
        console.error(err.response?.data || err.message);
        res.status(500).send("Failed to create VM");
    }
});
app.get("/music/album/:id", async (req, res) => {
    try {
        const response = await fetch(`https://api.deezer.com/album/${req.params.id}`);
        const data = await response.text();
        res.type("application/json").send(data);
    } catch {
        res.status(500).json({ error: "Failed To Fetch Album" });
    }
});
app.get("/music/artist/:id", async (req, res) => {
    try {
        const response = await fetch(`https://api.deezer.com/artist/${req.params.id}`);
        const data = await response.text();
        res.type("application/json").send(data);
    } catch {
        res.status(500).json({ error: "Failed To Fetch Artist" });
    }
});
app.get("/music/artist/:id/albums", async (req, res) => {
    try {
        const response = await fetch(`https://api.deezer.com/artist/${req.params.id}/albums`);
        const data = await response.text();
        res.type("application/json").send(data);
    } catch {
        res.status(500).json({ error: "Failed To Fetch Albums" });
    }
});
app.get("/music/artist/:id/top", async (req, res) => {
    try {
        const response = await fetch(`https://api.deezer.com/artist/${req.params.id}/top?limit=20`);
        const data = await response.text();
        res.type("application/json").send(data);
    } catch {
        res.status(500).json({ error: "Failed To Fetch Top Tracks" });
    }
});
app.get("/music/resolve", async (req, res) => {
    const { artist, title } = req.query;
    if (!artist || !title) {
        return res.status(400).json({ error: "Missing Artist Or Title" });
    }
    try {
        const q = encodeURIComponent(`${artist} ${title}`);
        const response = await fetch(`${SC_SEARCH_BASE}${q}&limit=5`);
        const data = await response.json();
        const hit = (data.collection || [])[0];
        if (!hit) {
            return res.status(404).json({ error: "Track Not Found On SoundCloud" });
        }
        const userPermalink  = hit.user.permalink;
        const trackPermalink = hit.permalink;
        res.json({
            userPermalink,
            trackPermalink,
            streamUrl:   SC_PLAY_URL(userPermalink, trackPermalink),
            downloadUrl: SC_DL_URL(userPermalink, trackPermalink),
            artUrl: hit.artwork_url
                ? hit.artwork_url.replace("-large", "-t500x500")
                : (hit.user?.avatar_url || null)
        });
    } catch (err) {
        res.status(500).json({ error: "Failed To Resolve Track" });
    }
});
app.get("/music/search", async (req, res) => {
    const q = req.query.q;
    try {
        const response = await fetch(`https://api.deezer.com/search?q=${encodeURIComponent(q)}`);
        const data = await response.text();
        res.type("application/json").send(data);
    } catch {
        res.status(500).json({ error: "Failed To Fetch Deezer" });
    }
});
app.get("/music/track/:id", async (req, res) => {
    try {
        const response = await fetch(`https://api.deezer.com/track/${req.params.id}`);
        const data = await response.text();
        res.type("application/json").send(data);
    } catch {
        res.status(500).json({ error: "Failed To Fetch Track" });
    }
});
app.get("/ping", (req, res) => {
    const now = Date.now();
    res.json({
        ok: true,
        serverTime: now
    });
});
app.get(ROUTES.DOWNLOAD_VIDEO, (req, res) => {
    const name = path.basename(req.params.name);
    const file = path.join(MOVIES_DIR, name + ".mp4");
    if (!file.startsWith(MOVIES_DIR) || !fs.existsSync(file)) return res.status(404).send("Not Found");
    res.download(file, `${name}.mp4`);
});
app.get(ROUTES.LIST_APPLY, (req, res) => {
    try {
        const diskFiles = new Set(
            fs.readdirSync(APPLY_DIR).filter(f => !f.endsWith(".json"))
        );
        let applyDataRaw = {};
        try {
            if (fs.existsSync(APPLY_JSON)) {
                applyDataRaw = JSON.parse(fs.readFileSync(APPLY_JSON, "utf8"));
            }
        } catch (e) {
            console.error("Failed to read apply.json:", e);
        }
        let applyData = [];
        if (applyDataRaw && typeof applyDataRaw === "object") {
            applyData = Object.entries(applyDataRaw).map(([file, data]) => ({
                file,
                ...data
            }));
        }
        const allFiles = new Set([
            ...diskFiles,
            ...applyData.map(a => a.file || a.filename).filter(Boolean),
            ...acceptStatus.keys()
        ]);
        const list = Array.from(allFiles).map(file => {
            const full = path.join(APPLY_DIR, file);
            let stats = null;
            if (fs.existsSync(full)) {
                try {
                    stats = fs.statSync(full);
                } catch {}
            }
            const statusObj = acceptStatus.get(file);
            let status = "idle";
            let percent = null;
            if (statusObj) {
                status = statusObj.status || "processing";
                if (statusObj.percent !== undefined) {
                    percent = String(Math.round(statusObj.percent));
                }
            }
            const applyEntry = applyData.find(a =>
                a.file === file || a.filename === file
            );            
            return {
                file,
                size: stats?.size || applyEntry?.size || 0,
                mtime: stats?.mtime || null,
                humanSize: stats ? formatBytes(stats.size) : "Processing...",
                status,
                percent,
                uploadedBy: applyEntry?.uploader || null
            };
        });
        res.json({
            ok: true,
            files: list,
            apply: applyDataRaw
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ ok: false });
    }
});
app.get(ROUTES.LIST_VIDEOS, (req, res) => {
    try {
        res.json({ ok: true, videos: listMovies() });
    } catch (e) {
        res.status(500).json({ ok: false });
    }
});
app.get(ROUTES.STREAM_APPLY, (req, res) => {
    try {
        const name = path.basename(req.params.name);
        const candidate = path.join(APPLY_DIR, name);
        if (!candidate.startsWith(APPLY_DIR) || !fs.existsSync(candidate)) return res.status(404).send("Not Found");
        const stat = fs.statSync(candidate);
        const total = stat.size;
        const range = req.headers.range;
        if (range) {
            const parts = /bytes=(\d+)-(\d*)/.exec(range);
            if (!parts) return res.status(416).send("Invalid Range");
            const start = parseInt(parts[1], 10);
            const end = parts[2] ? parseInt(parts[2], 10) : Math.min(start + 10 * 1024 * 1024 - 1, total - 1);
            if (start >= total) return res.status(416).send("Requested Range Not Satisfiable");
            const chunksize = end - start + 1;
            res.writeHead(206, {
                "Content-Range": `bytes ${start}-${end}/${total}`,
                "Accept-Ranges": "bytes",
                "Content-Length": chunksize,
                "Content-Type": "video/mp4",
                "Cache-Control": "no-cache",
            });
            fs.createReadStream(candidate, { start, end }).pipe(res);
        } else {
            res.writeHead(200, {
                "Content-Length": total,
                "Content-Type": "video/mp4",
                "Accept-Ranges": "bytes",
                "Cache-Control": "no-cache",
            });
            fs.createReadStream(candidate).pipe(res);
        }
    } catch (e) {
        console.error(e);
        res.status(500).send("Server Error");
    }
});
app.get(ROUTES.STREAM_VIDEO, (req, res) => {
    try {
        const name = path.basename(req.params.name);
        const candidate = path.join(MOVIES_DIR, name + ".mp4");
        if (!candidate.startsWith(MOVIES_DIR) || !fs.existsSync(candidate)) return res.status(404).send("Not Found");
        const stat = fs.statSync(candidate);
        const total = stat.size;
        const range = req.headers.range;
        if (range) {
            const parts = /bytes=(\d+)-(\d*)/.exec(range);
            if (!parts) return res.status(416).send("Invalid Range");
            const start = parseInt(parts[1], 10);
            const end = parts[2] ? parseInt(parts[2], 10) : Math.min(start + 10 * 1024 * 1024 - 1, total - 1);
            if (start >= total) return res.status(416).send("Requested Range Not Satisfiable");
            const chunksize = end - start + 1;
            res.writeHead(206, {
                "Content-Range": `bytes ${start}-${end}/${total}`,
                "Accept-Ranges": "bytes",
                "Content-Length": chunksize,
                "Content-Type": "video/mp4",
                "Cache-Control": "public, max-age=3600",
            });
            fs.createReadStream(candidate, { start, end }).pipe(res);
        } else {
            res.writeHead(200, {
                "Content-Length": total,
                "Content-Type": "video/mp4",
                "Accept-Ranges": "bytes",
                "Cache-Control": "public, max-age=3600",
            });
            fs.createReadStream(candidate).pipe(res);
        }
    } catch (e) {
        console.error(e);
        res.status(500).send("Server Error");
    }
});
app.get("/verify-user", verifyFirebaseToken, async (req, res) => {
    const { uid, token } = req.query;
    if (!uid) return res.status(400).send("Missing uid");
    let requesterUid = null;
    if (token) {
        try {
            const decoded = await admin.auth().verifyIdToken(token);
            requesterUid = decoded.uid;
        } catch {
            return res.status(401).send("Invalid token");
        }
    } else {
        return res.redirect(`/InfiniteAdmins.html?chat=true&verifyUid=${encodeURIComponent(uid)}`);
    }
    const profile = readDataPath(`users/${requesterUid}/profile`);
    if (!profile || !(profile.isOwner || profile.isTester || profile.isCoOwner || profile.isDev)) {
        return res.status(403).send("Not Authorized");
    }
    const targetProfile = readDataPath(`users/${uid}/profile`);
    if (!targetProfile) return res.status(404).send("User Not Found");
    if (targetProfile.verified) return res.send("User Already Verified");
    updateDataPath(`users/${uid}/profile`, { verified: true });
    logEvent("notifications", {
        id: `verified_${uid}_${Date.now()}`,
        data: { type: "userVerified", uid, verifiedBy: requesterUid }
    });
    console.log(`User ${uid} verified by ${requesterUid} via GET`);
    res.send(`<html><body style="background:#111;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0"><div style="text-align:center"><h2>✅ User Verified Successfully</h2><p>The user has been verified and can now access the chat.</p><a href="/InfiniteAdmins.html?chat=true" style="color:#4fa3ff">Back to Admin Chat</a></div></body></html>`);
});
app.get("/weather", async (req, res) => {
    try {
        const { city, state } = req.query;
        if (!city || !state) {
            return res.status(400).json({
                error: "Missing City Or State"
            });
        }
        const geoURL = `https://nominatim.openstreetmap.org/search?city=${encodeURIComponent(city)}&state=${encodeURIComponent(state)}&country=USA&format=json&limit=1`;
        const geoRes = await fetch(geoURL, {
            headers: { "User-Agent": "simple-weather-app" }
        });
        const geoData = await geoRes.json();
        if (!geoData.length) {
            return res.status(404).json({ error: "Location Not found" });
        }
        const lat = geoData[0].lat;
        const lon = geoData[0].lon;
        const pointRes = await fetch(`https://api.weather.gov/points/${lat},${lon}`, {
            headers: {
                "User-Agent": "simple-weather-app (support@infinitecampus.xyz)",
                "Accept": "application/geo+json"
            }
        });
        const pointData = await pointRes.json();
        const stationsURL = pointData.properties.observationStations;
        const stationRes = await fetch(stationsURL, {
            headers: { "User-Agent": "simple-weather-app" }
        });
        const stationData = await stationRes.json();
        const stationId = stationData.features[0].properties.stationIdentifier;
        const obsRes = await fetch(
            `https://api.weather.gov/stations/${stationId}/observations/latest`,
            { headers: { "User-Agent": "simple-weather-app" } }
        );
        const obsData = await obsRes.json();
        const tempC = obsData.properties.temperature.value;
        const condition = obsData.properties.textDescription || "Unknown";
        if (tempC === null) {
            return res.json({
                display: `${city}, ${state}: Weather Unavailable`
            });
        }
        const tempF = (tempC * 9/5) + 32;
        const roundF = Math.round(tempF);
        const roundC = Math.round(tempC);
        function getWeatherEmoji(text) {
            text = text.toLowerCase();
            if (text.includes("thunder")) return "⛈️";
            if (text.includes("snow")) return "❄️";
            if (text.includes("rain") || text.includes("shower")) return "🌧️";
            if (text.includes("drizzle")) return "🌦️";
            if (text.includes("fog") || text.includes("mist")) return "🌫️";
            if (text.includes("cloud")) return "☁️";
            if (text.includes("clear") || text.includes("sunny")) return "☀️";
            if (text.includes("wind")) return "💨";
            return "";
        }
        const emoji = getWeatherEmoji(condition);
        const display = `${city}, ${state}:${emoji} ${roundF}`;
        res.json({
            location: `${city}, ${state}`,
            temperature: {
                fahrenheit: roundF,
                celsius: roundC
            },
            condition,
            emoji,
            display,
            station: stationId,
            time: obsData.properties.timestamp
        });
    } catch (err) {
        res.status(500).json({ error: "Weather Lookup Failed" });
    }
});
app.post("/admin/createCustomToken", verifyFirebaseToken, async (req, res) => {
    try {
        const requesterUid = req.user.uid;
        const { targetUid } = req.body;
        if (!targetUid) {
            return res.status(400).json({ error: "Missing targetUid" });
        }
        const isOwner = readDataPath(`users/${requesterUid}/profile/isOwner`);
        if (!isOwner) {
            return res.status(403).json({ error: "Not authorized" });
        }
        const customToken = await admin.auth().createCustomToken(targetUid);
        const now = new Date();
        const expiresDate = new Date(Date.now() + 24 * 60 * 60 * 1000);
        const logs = loadAccLogs();
        logs[targetUid] = {
            token: customToken,
            expires: formatTimes(expiresDate),
            expiresRaw: expiresDate.getTime(),
            created: formatTimes(now),
            author: requesterUid,
            ip: getIP(req),
            uses: logs[targetUid]?.uses || 0
        };
        saveAccLogs(logs);
        const report = loadReportJSON();
        const day = now.getDate().toString();
        if (!report.report[day]) report.report[day] = {};
        if (!report.report[day]["tokens"]) report.report[day]["tokens"] = { count: 0 };
        report.report[day]["tokens"].count++;
        saveReportJSON(report);
        res.json({
            success: true,
            token: customToken,
            expires: logs[targetUid].expires
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to create token" });
    }
});
app.post("/admin/discord_toggle", async (req, res) => {
    const pass = req.headers["x-admin-password"];
    if (pass === process.env.NITRIX67 || pass === process.env.DON_PASS_1) {
        return res.status(403).json({
            error: "You Are Not Allowed To Use The Lockdown Services"
        });
    }
    if (!DISCORD_DISABLED) {
        DISCORD_DISABLED = true;
        try {
            await discordRequestForce({
                method: "post",
                url: `https://discord.com/api/v10/channels/${logid}/messages`,
                data: {
                    content: "**Live Discord Chat Has Been Locked Down**"
                },
                headers: { "Content-Type": "application/json" }
            });
        } catch {}
        return res.json({ discordDisabled: true });
    }
    DISCORD_DISABLED = false;
    try {
        await discordRequestForce({
            method: "post",
            url: `https://discord.com/api/v10/channels/${logid}/messages`,
            data: {
                content: "**Live Discord Chat Has Been Unlocked**"
            },
            headers: { "Content-Type": "application/json" }
        });
    } catch {}
    res.json({ discordDisabled: false });
});
app.post("/admin/lockdown", (req, res) => {
    const pass = req.headers["x-admin-password"];
    if (pass === process.env.NITRIX67 || pass === process.env.DON_PASS_1) {
        return res.status(403).json({
            error: "You Are Not Allowed To Use The Lockdown Services"
        });
    }
    LOCKDOWN = !LOCKDOWN;
    if (LOCKDOWN) {
        discordRequestForce({
            method: "post",
            url: `https://discord.com/api/v10/channels/${logid}/messages`,
            data: {
                content: "**File Uploads Have Been Locked Down**"
            },
            headers: { "Content-Type": "application/json" }
        });
    } else {
        discordRequestForce({
            method: "post",
            url: `https://discord.com/api/v10/channels/${logid}/messages`,
            data: {
                content: "**File Uploads Have Been Unlocked**"
            },
            headers: { "Content-Type": "application/json" }
        });
    }
    console.log(`LOCKDOWN Is Now ${LOCKDOWN ? "ON" : "OFF"} Via Remote Toggle`);
    res.json({ lockdown: LOCKDOWN });
});
app.post("/api/anon-name", (req, res) => {
    let { name, sessionToken } = req.body;
    if (!name || typeof name !== "string") return res.status(400).json({ error: "Missing name" });
    name = name.trim().slice(0, 32);
    if (!name) return res.status(400).json({ error: "Name cannot be empty" });
    const forbidden = /^(anonymous|admin|owner|system|bot|discord|hacker41|f3inti|yoyomaster95|nitrix67|gmacbride)/i;
    if (forbidden.test(name) && name.toLowerCase() !== "anonymous") {
        return res.status(400).json({ error: "That Name Is Reserved" });
    }
    if (!sessionToken || !anonSessions.has(sessionToken)) {
        sessionToken = crypto.randomBytes(24).toString("hex");
    }
    anonSessions.set(sessionToken, { name, createdAt: Date.now() });
    res.json({ sessionToken, name });
});
app.post(`/api/delete_apply_${UNIQUE_SUFFIX}`, express.json(), (req, res) => {
    const { filename } = req.body;
    if (!filename) return res.json({ ok: false, message: "No Filename Provided" });
    const full = path.join(APPLY_DIR, filename);
    if (!fs.existsSync(full)) return res.json({ ok: false, message: "Not Found" });
    try {
        fs.unlinkSync(full);
        finishReject(filename);
        applicantMessages.delete(filename);
        acceptStatus.delete(filename);
        return res.json({ ok: true });
    } catch (err) {
        return res.json({ ok: false, message: err.message });
    }
});
app.post("/auth/send-email-change", verifyFirebaseToken, async (req, res) => {
    try {
        const uid = req.user.uid;
        const { newEmail } = req.body;
        if (!newEmail) return res.status(400).json({ error: "newEmail Required" });
        const firebaseUser = await admin.auth().getUser(uid);
        const oldEmail = firebaseUser.email;
        const profile = readDataPath(`users/${uid}/profile`);
        const displayName = profile?.displayName || "User";
        const actionCodeSettings = {
            url: "https://www.infinitecampus.xyz/InfiniteAccounts.html",
            handleCodeInApp: false
        };
        const link = await admin.auth().generateVerifyAndChangeEmailLink(oldEmail, newEmail, actionCodeSettings);
        const url = new URL(link);
        const oobCode = url.searchParams.get("oobCode") || "";
        const action = url.searchParams.get("mode") || "verifyAndChangeEmail";
        await sendTemplatedEmail("email_change", oldEmail, "Confirm Your Infinite Campus Email Change", {
            DISPLAYNAME: displayName,
            EMAIL: oldEmail,
            EMAIL1: oldEmail,
            EMAIL2: newEmail,
            OOBCODE: oobCode,
            ACTION: action
        });
        res.json({ success: true });
    } catch (err) {
        console.error("[Auth Email] send-email-change error:", err.message);
        res.status(500).json({ error: err.message || "Failed To Send Email Change Link" });
    }
});
app.post("/auth/send-email-verify", verifyFirebaseToken, async (req, res) => {
    try {
        const uid = req.user.uid;
        const firebaseUser = await admin.auth().getUser(uid);
        if (firebaseUser.emailVerified) {
            return res.status(400).json({ error: "Email Already Verified" });
        }
        const email = firebaseUser.email;
        const profile = readDataPath(`users/${uid}/profile`);
        const displayName = profile?.displayName || "User";
        const actionCodeSettings = {
            url: "https://www.infinitecampus.xyz/InfiniteAccounts.html",
            handleCodeInApp: false
        };
        const link = await admin.auth().generateEmailVerificationLink(email, actionCodeSettings);
        const url = new URL(link);
        const oobCode = url.searchParams.get("oobCode") || "";
        const action = url.searchParams.get("mode") || "verifyEmail";
        await sendTemplatedEmail("email_verify", email, "Verify Your Infinite Campus Email", {
            DISPLAYNAME: displayName,
            EMAIL: email,
            OOBCODE: oobCode,
            ACTION: action
        });
        res.json({ success: true });
    } catch (err) {
        console.error("[Auth Email] send-email-verify Error:", err.message);
        res.status(500).json({ error: err.message || "Failed To Send Verification Email" });
    }
});
app.post("/auth/send-password-reset", async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: "Email required" });
         let displayName = "User";
        try {
            const firebaseUser = await admin.auth().getUserByEmail(email);
            const data = getDataCache();
            for (const [uid, userData] of Object.entries(data.users || {})) {
                if (userData?.settings?.userEmail === email || firebaseUser.uid === uid) {
                    displayName = userData?.profile?.displayName || "User";
                    break;
                }
            }
        } catch (_) {
            return;
        }
        const actionCodeSettings = {
            url: "https://www.infinitecampus.xyz/InfiniteAccounts.html",
            handleCodeInApp: false
        };
        const link = await admin.auth().generatePasswordResetLink(email, actionCodeSettings);
        const url = new URL(link);
        const oobCode = url.searchParams.get("oobCode") || "";
        const action = url.searchParams.get("mode") || "resetPassword";
        await sendTemplatedEmail("password_reset", email, "Reset Your Infinite Campus Password", {
            DISPLAYNAME: displayName,
            EMAIL: email,
            OOBCODE: oobCode,
            ACTION: action
        });
        res.json({ success: true });
    } catch (err) {
        console.error("[Auth Email] send-password-reset Error:", err.message);
        res.status(500).json({ error: err.message || "Failed To Send Reset Email" });
    }
});
app.post("/auth/send-two-factor", verifyFirebaseToken, async (req, res) => {
    try {
        const uid = req.user.uid;
        const { code } = req.body;
        if (!code) return res.status(400).json({ error: "Code Required" });
        const firebaseUser = await admin.auth().getUser(uid);
        const email = firebaseUser.email;
        const profile = readDataPath(`users/${uid}/profile`);
        const displayName = profile?.displayName || "User";
        await sendTemplatedEmail("two_factor", email, "Your Infinite Campus Two-Factor Code", {
            DISPLAYNAME: displayName,
            EMAIL: email,
            UID: uid,
            SECONDFACTOR: code
        });
        res.json({ success: true });
    } catch (err) {
        console.error("[Auth Email] send-two-factor Error:", err.message);
        res.status(500).json({ error: err.message || "Failed To Send 2FA Email" });
    }
});
app.post("/check_pass", (req, res) => {
    const pass = req.body.password;
    if (!pass) {
        return res.status(400).json({ error: "No Password Provided" });
    }
    const validPasswords = [
        process.env.ADMIN_PASSWORD,
        process.env.ADMIN_PASSWORD_2,
        process.env.DON_PASS_1,
        process.env.YOYOMASTER,
        process.env.NITRIX67
    ];
    if (validPasswords.includes(pass)) {
        return res.json({ ok: "true" });
    }
    console.log("Password Incorrect");
    return res.status(401).json({ status: "invalid" });
});
app.post("/delete", rateLimit("delete"), async (req, res) => {
    try {
        const uid = await verifyToken(req);
        const { path } = req.body;
        if (!Array.isArray(path)) {
            return res.status(400).json({ error: "Path must be array" });
        }
        const dataJson = getDataCache();
        const rules = await loadRules();
        const root = new DataSnapshot(dataJson);
        let parent = dataJson;
        for (let i = 0; i < path.length - 1; i++) {
            parent = parent?.[path[i]];
            if (parent == null) {
                return res.json({ success: true });
            }
        }
        const key = path[path.length - 1];
        const oldValue = parent?.[key];
        const dataSnap = new DataSnapshot(oldValue);
        const newDataSnap = new DataSnapshot(null);
        const userProfile = dataJson?.users?.[uid]?.profile || {};
        const auth = { uid, ...userProfile };
        const isHighAdmin = !!(userProfile.isOwner || userProfile.isCoOwner || userProfile.isTester || userProfile.isHAdmin);
        const isAnonMessage = oldValue && (oldValue.sender === "anon" || (oldValue.anon === true && !oldValue.s));
        const { rule, wildcards } = getRuleForOperation(rules, path, "write");
        if (
            !(isHighAdmin && isAnonMessage) &&
            (
                !rule ||
                !evaluate(rule, {
                    auth,
                    root,
                    data: dataSnap,
                    newData: newDataSnap,
                    wildcards,
                })
            )
        ) {
            return res.status(403).json({ error: "Delete denied" });
        }
        const validateRule = getRuleForOperation(rules, path, "validate").rule;
        if (
            !(isHighAdmin && isAnonMessage) &&
            validateRule &&
            !evaluate(validateRule, {
                auth,
                root,
                data: dataSnap,
                newData: newDataSnap,
                wildcards,
            })
        ) {
            return res.status(403).json({ error: "Validation failed" });
        }
        delete parent[key];
        saveData(dataJson);
        broadcastUpdate(path, null);
        if (path.length === 3 && path[0] === "messages" && DISCORD_CHANNEL_MAP[path[1]]) {
            bridgeDeleteToDiscordWithEntry(path[1], path[2], oldValue).catch(() => {});
        }
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(401).json({ error: "Unauthorized" });
    }
});
app.post("/discord-channel-map", verifyFirebaseToken, async (req, res) => {
    try {
        const uid = req.user.uid;
        const profile = readDataPath(`users/${uid}/profile`);
        if (!profile || !(profile.isOwner || profile.isCoOwner || profile.isTester)) {
            return res.status(403).json({ error: "Not Authorized" });
        }
        const { channelName, discordChannelId } = req.body;
        if (!channelName || typeof channelName !== "string") {
            return res.status(400).json({ error: "Missing channelName" });
        }
        if (discordChannelId && !/^\d+$/.test(discordChannelId)) {
            return res.status(400).json({ error: "Invalid Discord Channel ID" });
        }
        if (discordChannelId) {
            DISCORD_CHANNEL_MAP[channelName] = discordChannelId;
        } else {
            delete DISCORD_CHANNEL_MAP[channelName];
        }
        saveDiscordChannelMap();
        console.log(`Channel Map Updated: ${channelName} -> ${discordChannelId || "(Removed)"}`);
        res.json({ ok: true, map: DISCORD_CHANNEL_MAP });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
app.post("/discordVerify", verifyFirebaseToken, async (req, res) => {
    try {
        const { username, uid } = req.body;
        if (!username || !uid) {
            return res.status(400).json({ error: "Missing Username Or Uid" });
        }
        const GUILD_ID = process.env.DISCORD_GUILD_ID;
        const response = await axios.get(
            `https://discord.com/api/v10/guilds/${GUILD_ID}/members/search`,
            {
                params: { query: username, limit: 10 },
                headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` }
            }
        );
        const members = response.data;
        const found = members.find(m =>
            m.user.username.toLowerCase() === username.toLowerCase()
        );
        if (!found) {
            return res.json({ message: "Not In Server" });
        }
        const discordId = found.user.id;
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        discordVerifications.set(uid, {
            discordId,
            username,
            code,
            created: Date.now()
        });
        await axios.post(
            `https://discord.com/api/v10/users/@me/channels`,
            { recipient_id: discordId },
            { headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } }
        ).then(async dm => {
            await axios.post(
                `https://discord.com/api/v10/channels/${dm.data.id}/messages`,
                {
                    content: `This Code Is For Discord Verification\nYour Verification Code Is: **${code}**\nIf You Did Not Request Verification, You Can Ignore This Message.`
                },
                { headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } }
            );
        });
        res.json({
            success: true,
            message: "Verification Code Sent Via Discord DM"
        });
    } catch (err) {
        console.error("Discord Verify Error:", err.response?.data || err.message);
        res.status(500).json({ error: "Verification failed" });
    }
});
app.post("/discordVerifyCancel", (req, res) => {
    const { uid } = req.body;
    if (discordVerifications.has(uid)) {
        discordVerifications.delete(uid);
    }
    res.json({
        success: true,
        message: "Verification Cancelled"
    });
});
app.post("/discordVerifyConfirm", async (req, res) => {
    const { uid, code } = req.body;
    const verify = discordVerifications.get(uid);
    if (!verify) {
        return res.status(400).json({ error: "No Verification In Progress" });
    }
    if (verify.code !== code) {
        return res.status(400).json({ error: "Invalid Code" });
    }
    updateDataPath(`users/${uid}/profile`, { dUsername: verify.username });
    discordVerifications.delete(uid);
    res.json({
        success: true,
        message: "Discord Account Verified"
    });
});
app.post("/email", verifyFirebaseToken, async (req, res) => {
    try {
        const uid = req.user.uid;
        const profile = readDataPath(`users/${uid}/profile`);
        if (!profile || !(profile.isOwner || profile.isCoOwner || profile.isTester)) {
            return res.status(403).json({ error: "Not Authorized" });
        }
        const { to, subject, text, html } = req.body;
        if (!to || !subject || (!text && !html)) {
            return res.status(400).json({
                success: false,
                error: "Missing to, subject, and text/html"
            });
        }
        const result = await resend.emails.send({
            from: "support@infinitecampus.xyz",
            to,
            subject,
            text,
            html
        });
        try {
            const senderProfile = readDataPath(`users/${uid}/profile`);
            const senderName = senderProfile?.displayName || uid;
            const preview = (text || "").substring(0, 200) || "(HTML only)";
            await discordRequest({
                method: "post",
                url: `https://discord.com/api/v10/channels/${logid}/messages`,
                data: {
                    embeds: [{
                        title: "Email Sent",
                        color: 0x4fa3ff,
                        fields: [
                            { name: "From", value: senderName, inline: true },
                            { name: "To", value: Array.isArray(to) ? to.join(", ") : to, inline: true },
                            { name: "Subject", value: subject, inline: false },
                            { name: "Preview", value: preview, inline: false },
                        ],
                        timestamp: new Date().toISOString(),
                        footer: { text: `Resend ID: ${result.data?.id || "N/A"}` }
                    }]
                }
            });
        } catch (logErr) {
            console.error("Email Log To Discord Failed:", logErr.message || logErr);
        }
        res.json({
            success: true,
            id: result.data?.id || null
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({
            success: false,
            error: err.message
        });
    }
});
app.post("/github-webhook", express.json({ type: "application/json" }),async (req, res) => {    
    const event = req.headers["x-github-event"];
    const payload = req.body;
    try {
        let embed = {
            color: 0x92C83E,
            timestamp: new Date().toISOString()
        };
        if (event === "push") {
            const allAuto = payload.commits.every(c =>
                c.message.toLowerCase().startsWith("auto")
            );
            if (allAuto) {
                return res.sendStatus(200);
            }
            const commit = payload.commits[0];
            embed.title = "New Commit";
            embed.description = commit.message;
            embed.author = {
                name: `${payload.pusher.name} Committed`,
                icon_url: payload.sender.avatar_url
            };
            embed.url = commit.url;
        } else if (event === "release") {
            embed.title = "New Release";
            embed.description = payload.release.body || "No Description";
            embed.author = {
                name: `${payload.sender.login} Published A Release`,
                icon_url: payload.sender.avatar_url
            };
            embed.url = payload.release.html_url;
        } else if (event === "star") {
            embed.title = "Repository Star";
            embed.description = payload.repository.full_name;
            embed.author = {
                name: `${payload.sender.login} Starred The Repo`,
                icon_url: payload.sender.avatar_url
            };
        } else if (event === "fork") {
            embed.title = "Repository Forked";
            embed.description = payload.forkee.full_name;
            embed.author = {
                name: `${payload.sender.login} Forked The Repo`,
                icon_url: payload.sender.avatar_url
            };
        } else if (event === "issues") {
            embed.title = `Issue ${payload.action}`;
            embed.description = payload.issue.title;
            embed.author = {
                name: `${payload.sender.login} ${payload.action} An Issue`,
                icon_url: payload.sender.avatar_url
            };
            embed.url = payload.issue.html_url;
        } else if (event === "pull_request") {
            embed.title = `Pull Request ${payload.action}`;
            embed.description = payload.pull_request.title;
            embed.author = {
                name: `${payload.sender.login} ${payload.action} A PR`,
                icon_url: payload.sender.avatar_url
            };
            embed.url = payload.pull_request.html_url;
        } else {
            embed.title = `GitHub Event: ${event}`;
            embed.description = `Triggered By ${payload.sender?.login || "Unknown User"}`;
            embed.author = {
                name: payload.sender?.login || "GitHub",
                icon_url: payload.sender?.avatar_url
            };
        }
        await sendDiscordEmbed(embed);
        res.sendStatus(200);
    } catch (err) {
        console.error(err);
        res.sendStatus(500);
    }
});
app.post("/limit-to-last", async (req, res) => {
    try {
        let uid = null;
        let auth = null;
        const header = req.headers.authorization;
        if (header?.startsWith("Bearer ")) {
            try {
                uid = (await admin.auth().verifyIdToken(header.split("Bearer ")[1])).uid;
            } catch {
                return res.status(401).json({ error: "Invalid Token" });
            }
        }
        const { path, limit = 50 } = req.body;
        if (!Array.isArray(path)) return res.status(400).json({ error: "Path Must Be Array" });
        const dataJson = getDataCache();
        const rules = await loadRules();
        const root = new DataSnapshot(dataJson);
        if (uid) auth = { uid, ...dataJson?.users?.[uid]?.profile };
        const { rule, wildcards } = getRuleForOperation(rules, path, "read");
        if (!rule || !evaluate(rule, { auth, root, data: new DataSnapshot(dataJson), newData: new DataSnapshot(dataJson), wildcards }))
            return res.status(403).json({ error: "Permission denied" });
        let current = dataJson;
        for (const p of path) current = current?.[p];
        if (current && typeof current === "object" && !Array.isArray(current)) {
            const keys = Object.keys(current).slice(-limit);
            current = keys.reduce((acc, k) => { acc[k] = current[k]; return acc; }, {});
        } else if (Array.isArray(current)) {
            current = current.slice(-limit);
        }
        const filtered = filterDataByRules(current, path, auth, root, rules);
        res.json({ data: filtered });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Server error" });
    }
});
app.post("/load-more-messages", async (req, res) => {
    try {
        let uid = null;
        let auth = null;
        const header = req.headers.authorization;
        if (header?.startsWith("Bearer ")) {
            try {
                uid = (await admin.auth().verifyIdToken(header.split("Bearer ")[1])).uid;
            } catch {
                return res.status(401).json({ error: "Invalid token" });
            }
        }
        const { path, before } = req.body;
        const limit = Math.min(req.body.limit || 25, 50);
        if (!Array.isArray(path)) {
            return res.status(400).json({ error: "Path Must Be Array" });
        }
        if (typeof before !== "number") {
            return res.status(400).json({ error: "Before Must Be A Number (Timestamp)" });
        }
        const dataJson = getDataCache();
        const rules = await loadRules();
        const root = new DataSnapshot(dataJson);
        if (uid) {
            const userProfile = dataJson?.users?.[uid]?.profile || {};
            auth = { uid, ...userProfile };
        }
        const { rule, wildcards } = getRuleForOperation(rules, path, "read");
        if (rule) {
            const allowed = evaluate(rule, { auth, root, data: root, newData: root, wildcards });
            if (!allowed) return res.json({ data: null });
        }
        let node = dataJson;
        for (const p of path) node = node?.[p];
        if (!node || typeof node !== "object") {
            return res.json({ data: null });
        }
        const filtered = Object.entries(node).filter(([k, v]) => {
            if (!v || typeof v !== "object") return false;
            const ts = typeof v.timestamp === "number" ? v.timestamp : Number(k);
            return !isNaN(ts) && ts < before;
        });
        filtered.sort(([ka, va], [kb, vb]) => {
            const tsA = typeof va.timestamp === "number" ? va.timestamp : Number(ka);
            const tsB = typeof vb.timestamp === "number" ? vb.timestamp : Number(kb);
            return tsB - tsA;
        });
        const entries = filtered.slice(0, limit);
        if (entries.length === 0) {
            return res.json({ data: null });
        }
        const result = entries.map(([k, v]) => ({
            id: k,
            timestamp: typeof v.timestamp === "number" ? v.timestamp : Number(k),
            ...v
        }));
        res.json({ data: result });
    } catch (err) {
        console.error("Load More Messages Error", err);
        res.status(500).json({ error: "Server Error" });
    }
});
app.post("/online", verifyFirebaseToken, rateLimit("online"), async (req, res) => {
    try {
        const uid = req.user.uid;
        updateDataPath(`users/${uid}/profile`, { online: true });
        onlineLastSeen.set(uid, Date.now());
        res.json({
            success: true
        });
    } catch{}
});
app.post("/pay", verifyFirebaseToken, async (req, res) => {
    try {
        const uid = req.user.uid;
        const { token, amount } = req.body;
        if (!token || !amount) {
            return res.status(400).json({ error: "Missing Token Or Amount" });
        }
        const response = await client.paymentsApi.createPayment({
            sourceId: token,
            idempotencyKey: crypto.randomUUID(),
            amountMoney: {
                amount,
                currency: "USD",
            },
            locationId: process.env.SQUARE_LOCATION_ID,
            note: uid,
        });
        const safeResult = JSON.parse(
            JSON.stringify(response.result, (_, value) =>
                typeof value === "bigint" ? value.toString() : value
            )
        );
        const payment = safeResult?.payment;
        if (payment && payment.status !== "COMPLETED") {
            const declinedAmount = payment.amount_money?.amount ?? req.body.amount;
            const declineReason = payment.status || "UNKNOWN";
            console.warn(`Payment declined for uid ${uid}: status=${declineReason}`);
            discordRequestForce({
                method: "post",
                url: `https://discord.com/api/v10/channels/${logid}/messages`,
                data: {
                    content: `**Payment Declined**\nUser: \`${uid}\`\nAmount: $${(declinedAmount / 100).toFixed(2)}\nStatus: \`${declineReason}\``
                },
                headers: { "Content-Type": "application/json" }
            }).catch(err => console.error("Failed to send declined payment log:", err));
        }
        res.json(safeResult);
    } catch (err) {
        console.error("Payment Error:", err);
        if (err instanceof Error) {
            res.status(500).json({ error: err.message });
        } else {
            res.status(500).json({ error: "Unknown Error" });
        }
    }
});
app.post("/react", verifyFirebaseToken, rateLimit("react"), async (req, res) => {
    try {
        const uid = req.user.uid;
        const { path: msgPath, emoji, channel } = req.body;
        if (!Array.isArray(msgPath) || !emoji || typeof emoji !== "string") {
            return res.status(400).json({ error: "Missing path or emoji" });
        }
        if (emoji.length > 8) {
            return res.status(400).json({ error: "Invalid emoji" });
        }
        const dataJson = getDataCache();
        let msg = dataJson;
        for (const p of msgPath) msg = msg?.[p];
        if (!msg || typeof msg !== "object") {
            return res.status(404).json({ error: "Message not found" });
        }
        const reactions = msg.reactions ? { ...msg.reactions } : {};
        const emojiReactors = reactions[emoji] ? { ...reactions[emoji] } : {};
        const alreadyReacted = !!emojiReactors[uid];
        if (alreadyReacted) {
            delete emojiReactors[uid];
            if (Object.keys(emojiReactors).length === 0) {
                delete reactions[emoji];
            } else {
                reactions[emoji] = emojiReactors;
            }
        } else {
            if (!reactions[emoji] && Object.keys(reactions).length >= MAX_REACTIONS_PER_MSG) {
                return res.status(400).json({ error: `Max ${MAX_REACTIONS_PER_MSG} different reactions per message` });
            }
            let userReactionCount = 0;
            for (const e of Object.keys(reactions)) {
                if (reactions[e]?.[uid]) userReactionCount++;
            }
            if (userReactionCount >= MAX_REACTIONS_PER_USER_MSG) {
                return res.status(400).json({ error: `Max ${MAX_REACTIONS_PER_USER_MSG} reactions per user per message` });
            }
            reactions[emoji] = { ...emojiReactors, [uid]: true };
            const authorUid = msg.sender;
            if (authorUid && authorUid !== uid) {
                const msgId = msgPath[msgPath.length - 1];
                sendReactionNotification(authorUid, uid, emoji, channel || msgPath[1] || "General", msgId).catch(() => {});
            }
        }
        let parent = dataJson;
        for (let i = 0; i < msgPath.length - 1; i++) parent = parent[msgPath[i]] ||= {};
        const msgKey = msgPath[msgPath.length - 1];
        parent[msgKey] = { ...parent[msgKey], reactions };
        saveData(dataJson);
        broadcastUpdate(msgPath, parent[msgKey]);
        res.json({ success: true, reactions });
    } catch (err) {
        console.error("/react error:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});
app.post("/read", rateLimit("read"), async (req, res) => {
    try {
        let uid = null;
        let auth = null;
        const header = req.headers.authorization;
        if (header?.startsWith("Bearer ")) {
            try {
                uid = (await admin.auth().verifyIdToken(header.split("Bearer ")[1])).uid;
            } catch {
                return res.status(401).json({ error: "Invalid token" });
            }
        }
        const { path } = req.body;
        if (!Array.isArray(path)) return res.status(400).json({ error: "Path must be array" });
        const dataJson = getDataCache();
        const rules = await loadRules();
        const root = new DataSnapshot(dataJson);
        if (uid) {
            const userProfile = dataJson?.users?.[uid]?.profile || {};
            auth = { uid, ...userProfile };
        }
        let current = dataJson;
        for (const p of path) current = current?.[p];
        const dataSnap = new DataSnapshot(current);
        const { rule, wildcards } = getRuleForOperation(rules, path, "read");
        let allowed = true;
        if (rule) {
            allowed = evaluate(rule, { auth, root, data: dataSnap, newData: dataSnap, wildcards });
        }
        if (!allowed) {
            return res.json({ data: null });
        }
        const filteredData = filterDataByRules(current, path, auth, root, rules);
        res.json({ data: filteredData ?? null });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Server error" });
    }
});
app.post(ROUTES.UPLOAD, express.raw({ limit: "5mb", type: "*/*" }), (req, res) => {
    const uid = req.headers["x-user-id"] || "unknown";
    const uploadedBy = uid;
    try {
        const fileId = req.headers.fileid;
        const chunkIndex = Number(req.headers.chunkindex);
        const totalChunks = Number(req.headers.totalchunks);
        const filename = req.headers.filename;
        if (!fileId || chunkIndex === undefined || !totalChunks || !filename) {
            return res.status(400).json({ ok: false, message: "Missing Chunk Metadata" });
        }
        const safeFile = safeName(filename);
        const chunkDir = path.join(UPLOADS_TEMP_DIR, fileId);
        if (!fs.existsSync(chunkDir)) fs.mkdirSync(chunkDir, { recursive: true });
        const chunkPath = path.join(chunkDir, `chunk_${chunkIndex}`);
        fs.writeFileSync(chunkPath, req.body);
        tempUploadActivity.set(fileId, Date.now());
        const received = fs.readdirSync(chunkDir).length;
        if (received < totalChunks) {
            return res.json({
                ok: true,
                received,
                total: totalChunks,
                percent: Math.round((received / totalChunks) * 100)
            });
        }
        const finalPath = path.join(APPLY_DIR, safeFile);
        const writeStream = fs.createWriteStream(finalPath);
        (async () => {
            try {
                for (let i = 0; i < totalChunks; i++) {
                    const chunkPath = path.join(chunkDir, `chunk_${i}`);
                    await new Promise((resolve, reject) => {
                        const rs = fs.createReadStream(chunkPath);
                        rs.on("error", reject);
                        rs.on("end", resolve);
                        rs.pipe(writeStream, { end: false });
                    });
                }
                writeStream.end();
                writeStream.on("close", () => {
                    fs.rmSync(chunkDir, { recursive: true, force: true });
                    const metaPath = path.join(APPLY_DIR, safeFile + ".json");
                    fs.writeFileSync(metaPath, JSON.stringify({
                        uploadedBy,
                        uid
                    }));
                    const fileSize = fs.statSync(finalPath).size;
                    updateApply(safeFile, {
                        size: fileSize,
                        uploader: uploadedBy,
                        timestamp: Date.now()
                    });
                    logEvent("submitted-movies", {
                        id: safeFile,
                        data: {
                            author: uploadedBy,
                            accepted: "pending"
                        }
                    });
                    res.json({
                        ok: true,
                        filename: safeFile,
                        size: fileSize
                    });
                    let movieName = `${safeFile}`;
                    let watchLink = 'https://www.infinitecampus.xyz/InfiniteAdmins.html?movies=true';
                    let rejectLink = `${watchLink}`;
                    let acceptLink = `${watchLink}`;
                    sendApplicantEmbed(movieName, acceptLink, watchLink, rejectLink, fileSize);
                });
            } catch (err) {
                writeStream.destroy();
                console.error("Chunk Merge Failed:", err);
                res.status(500).json({ ok: false, message: "Failed To Assemble File" });
            }
        })();
    } catch (err) {
        console.error("Chunk Upload Error:", err);
        res.status(500).json({ ok: false, message: err.message });
    }
});
app.post("/square-webhook",
    express.raw({ type: "application/json" }),
    async (req, res) => {
        try {
            const signature = req.headers['x-square-hmacsha256-signature'];
            const isValid = WebhooksHelper.isValidWebhookEventSignature(
                req.body,
                signature,
                SQUARE_SIGNATURE_KEY,
                SQUARE_WEBHOOK_URL
            );
            if (!isValid) {
                console.log("Webhook Signature Verification Failed.");
                return res.sendStatus(403);
            }
            const event = JSON.parse(req.body.toString());
            if (event.type === "payment.created") {
                const payment = event.data.object.payment;
                const uid = payment.note;
                const amount = payment.amount_money.amount;
                const amountDollars = amount / 100;
                const donationData = getDataCache();
                if (!donationData.donations) donationData.donations = {};
                donationData.donations.amount = (donationData.donations.amount || 0) + amountDollars;
                saveData(donationData);
                if (uid) {
                    await grantPremium(uid, amount);
                    logEvent("payments", {
                        id: payment.id || `payment_${Date.now()}`,
                        data: {
                            author: uid,
                            amount: `$${(amount / 100).toFixed(2)}`
                        }
                    });
                }
            }
            res.sendStatus(200);
        } catch (err) {
            console.error("Error Processing Square Webhook:", err);
            res.sendStatus(500);
        }
    }
);
app.post("/tokenUsed", async (req, res) => {
    const { uid } = req.body;
    if (!uid) return res.sendStatus(400);
    const logs = loadAccLogs();
    if (logs[uid]) {
        logs[uid].uses = (logs[uid].uses || 0) + 1;
        saveAccLogs(logs);
    }
    res.sendStatus(200);
});
app.post("/upload-pfp", verifyFirebaseToken, uploadPfp.single("file"), async (req, res) => {
    try {
        const { uid } = req.body;
        const file = req.file;
        if (!uid) {
            return res.status(400).json({ error: "Missing Firebase UID" });
        }
        const now = Date.now();
        const lastUpload = pfpUploadCooldown.get(uid);
        if (lastUpload && now - lastUpload < PFP_COOLDOWN_MS) {
            const remaining = Math.ceil((PFP_COOLDOWN_MS - (now - lastUpload)) / 1000);
            return res.status(429).json({
                error: `You Must Wait ${remaining} Seconds Before Uploading Another PFP`
            });
        }
        pfpUploadCooldown.set(uid, now);
        if (!file) {
            return res.status(400).json({ error: "No File Uploaded" });
        }
        const ext = path.extname(file.originalname).toLowerCase();
        if (!ALLOWED_PFP_EXTS.has(ext)) {
            return res.status(400).json({ error: "Invalid File Type" });
        }
        const indexRes = await fetch("https://www.infinitecampus.xyz/pfps/index.json");
        if (!indexRes.ok) {
            return res.status(500).json({ error: "Failed To Fetch index.json" });
        }
        const indexJson = await indexRes.json();
        const numbers = indexJson.map(name =>
            parseInt(name.split(".")[0], 10)
        ).filter(n => !isNaN(n));
        const nextNumber = (numbers.length > 0 ? numbers.reduce((a, b) => Math.max(a, b), 0) : 0) + 1;
        const newFileName = `${nextNumber}${ext}`;
        const newPicIndex = indexJson.length;
        indexJson.push(newFileName);
        const updatedIndexContent = Buffer.from(
            JSON.stringify(indexJson, null, 2)
        ).toString("base64");
        const githubToken = process.env.GITHUB_TOKEN;
        const owner = "InfiniteCampus41";
        const repo = "InfiniteCampus";
        const branch = "main";
        const shaRes = await axios.get(
            `https://api.github.com/repos/${owner}/${repo}/contents/pfps/index.json`,
            {
                headers: {
                    Authorization: `token ${githubToken}`,
                    "X-GitHub-Event": "ignore"
                }
            }
        );
        const currentSha = shaRes.data.sha;
        await axios.put(
            `https://api.github.com/repos/${owner}/${repo}/contents/pfps/index.json`,
            {
                message: "Auto Add PFP",
                content: updatedIndexContent,
                sha: currentSha,
                branch
            },
            {
                headers: {
                    Authorization: `token ${githubToken}`,
                    "X-GitHub-Event": "ignore"
                }
            }
        );
        const fileContent = file.buffer.toString("base64");
        await axios.put(
            `https://api.github.com/repos/${owner}/${repo}/contents/pfps/${newFileName}`,
            {
                message: "Auto Upload PFP",
                content: fileContent,
                branch
            },
            {
                headers: {
                    Authorization: `token ${githubToken}`,
                    "X-GitHub-Event": "ignore"
                }
            }
        );
        updateDataPath(`users/${uid}/profile`, { pic: newPicIndex });
        res.json({
            success: true,
            file: newFileName,
            picIndex: newPicIndex
        });
        await cleanupAndReindexPfps();
    } catch (err) {
        console.error("PFP Upload Error:", err.response?.data || err.message);
        res.status(500).json({ error: "Upload Failed" });
    }
});
app.post("/uploadthis", verifyFirebaseToken, uploadChunk.single("file"), async (req, res) => {
    if (LOCKDOWN) return res.status(403).json({ error: "Uploads Locked Down" });
    try {
        const userId = req.user?.uid;
        let maxAllowedSize = MAX_SIZE_NON_PREMIUM;
        if (userId) {
            try {
                const _upProfile = getDataCache()?.users?.[userId]?.profile || {};
                const isPremium =
                    _upProfile.premium1 || _upProfile.premium2 || _upProfile.premium3 ||
                    _upProfile.isDev || _upProfile.isAdmin || _upProfile.isHAdmin ||
                    _upProfile.isCoOwner || _upProfile.isTester || _upProfile.isOwner || _upProfile.isPartner;
                if (isPremium) {
                    maxAllowedSize = MAX_SIZE_PREMIUM;
                }
            } catch (err) {
                console.error("Premium check failed:", err);
            }
        }
        const fileId = req.headers["x-file-id"];
        const chunkNumber = parseInt(req.headers["x-chunk-number"], 10);
        const totalChunks = parseInt(req.headers["x-total-chunks"], 10);
        const originalFilename = req.headers["x-filename"];
        if (!fileId || isNaN(chunkNumber) || isNaN(totalChunks) || !originalFilename) {
            return res.status(400).json({ error: "Missing Required Headers For Chunked Upload" });
        }
        if (!req.file) {
            return res.status(400).json({ error: "No file chunk received" });
        }
        const tmpDir = path.join(UPLOADS_DIR, "tmp", fileId);
        await fs.promises.mkdir(tmpDir, { recursive: true });
        const chunkPath = path.join(tmpDir, `chunk-${chunkNumber}`);
        fs.writeFileSync(chunkPath, req.file.buffer);
        const chunkFiles = fs.readdirSync(tmpDir);
        if (chunkFiles.length === totalChunks) {
            const safeFileName = sanitize(originalFilename);
            const finalFilename = `${Date.now()}-${safeFileName}`;
            const finalPath = path.join(UPLOADS_DIR, finalFilename);
            const finalStream = fs.createWriteStream(finalPath);
            for (let i = 1; i <= totalChunks; i++) {
                const chunkFile = path.join(tmpDir, `chunk-${i}`);
                await new Promise((resolve, reject) => {
                    const rs = fs.createReadStream(chunkFile);
                    rs.on("error", reject);
                    rs.on("end", resolve);
                    rs.pipe(finalStream, { end: false });
                });
                fs.unlinkSync(chunkFile);
            }
            finalStream.end();
            fs.rmdirSync(tmpDir);
            let deleteDelay = AUTO_DELETE_MS;
            try {
                if (userId) {
                    const _upProfile2 = getDataCache()?.users?.[userId]?.profile || {};
                    const isPremium =
                        _upProfile2.premium1 || _upProfile2.premium2 || _upProfile2.premium3 ||
                        _upProfile2.isDev || _upProfile2.isAdmin || _upProfile2.isHAdmin ||
                        _upProfile2.isCoOwner || _upProfile2.isTester || _upProfile2.isOwner || _upProfile2.isPartner;
                    if (isPremium) {
                        deleteDelay = AUTO_DELETE_PM_MS;
                    }
                }
            } catch (err) {
                console.error("Delete timing check failed:", err);
            }
            setTimeout(() => fs.unlink(finalPath, () => {}), deleteDelay);
            pushUploadLog(finalFilename, req.file.size);
            return res.json({
                fileUrl: `${req.protocol}://${req.get("host")}/files/${finalFilename}`,
                message: "File Uploaded And Combined Successfully"
            });
        } else {
            return res.json({
                message: `Chunk ${chunkNumber} Uploaded Successfully`
            });
        }
    } catch (err) {
        console.error("Upload Error:", err);
        res.status(500).json({ error: "Upload Failed" });
    }
});
app.post("/verify-user", verifyFirebaseToken, async (req, res) => {
    try {
        const requesterUid = req.user.uid;
        const profile = readDataPath(`users/${requesterUid}/profile`);
        if (!profile || !(profile.isOwner || profile.isTester || profile.isCoOwner || profile.isDev)) {
            return res.status(403).json({ error: "Not Authorized" });
        }
        const { uid } = req.body;
        if (!uid) return res.status(400).json({ error: "Missing uid" });
        const targetProfile = readDataPath(`users/${uid}/profile`);
        if (!targetProfile) return res.status(404).json({ error: "User Not Found" });
        if (targetProfile.verified) return res.json({ success: true, message: "User Already Verified" });
        updateDataPath(`users/${uid}/profile`, { verified: true });
        logEvent("notifications", {
            id: `verified_${uid}_${Date.now()}`,
            data: { type: "userVerified", uid, verifiedBy: requesterUid }
        });
        console.log(`User ${uid} verified by ${requesterUid}`);
        res.json({ success: true, message: "User Verified" });
    } catch (err) {
        console.error("verify-user error:", err);
        res.status(500).json({ error: err.message || "Internal Server Error" });
    }
});
app.post("/write", rateLimit("write"), (req, res, next) => {
    let memoryUpload = multer({
        storage: multer.memoryStorage(),
        limits: {
            fileSize: 10 * 1024 * 1024
        }
    });
    memoryUpload.single("file")(req, res, (err) => {
        if (err) {
            if (err instanceof multer.MulterError && err.code === "LIMIT_FILE_SIZE") {
                return res.status(400).json({ error: "File size must be 10MB or less." });
            }
            return res.status(400).json({ error: err.message });
        }
        next();
    });
}, async (req, res) => {
        try {
        let uid = null;
        try { uid = await verifyToken(req); } catch { uid = null; }
        let path = req.body?.path;
        let value = req.body?.value;
        if (typeof path === "string") {
            try { path = JSON.parse(path); } catch {}
        }
        if (typeof value === "string") {
            try { value = JSON.parse(value); } catch {}
        }
        const uploadedFile = req.file || null;
        if (!Array.isArray(path)) return res.status(400).json({ error: "Path Must Be Array" });
        if (!uid) {
            const isNewMessage = path.length === 3 && path[0] === "messages";
            const isEdit      = path.length === 4 && path[0] === "messages";
            const isDelete    = value === null;
            if (isEdit || isDelete) {
                return res.status(403).json({ error: "Guests Cannot Edit Or Delete Messages." });
            }
            if (!isNewMessage) {
                return res.status(403).json({ error: "Unauthorized" });
            }
            const channelName = path[1];
            const dataJsonG = getDataCache();
            const chDataG = dataJsonG?.channels?.[channelName];
            if (!chDataG?.guestWrite) {
                return res.status(403).json({ error: "This Channel Does Not Allow Guest Messages." });
            }
            const anonSessionToken = req.headers["x-anon-session"] || req.body?.anonSession || null;
            const anonName = resolveAnonName(anonSessionToken);
            const msgText = (value?.t || value?.text || "").trim();
            if (!msgText && !uploadedFile) return res.status(400).json({ error: "Empty Message" });
            if (/@everyone\b/i.test(msgText) || /@here\b/i.test(msgText)) {
                return res.status(403).json({ error: "@everyone And @here Are Not Allowed." });
            }
            if (msgText.length > 500) {
                return res.status(400).json({ error: "Guest Messages Are Limited To 500 Characters." });
            }
            const ts = Date.now();
            const guestMsg = { u: anonName, t: msgText, sender: "anon" };
            if (value?.r) guestMsg.r = value.r;
            const dataJsonW = getDataCache();
            if (!dataJsonW.messages) dataJsonW.messages = {};
            if (!dataJsonW.messages[channelName]) dataJsonW.messages[channelName] = {};
            dataJsonW.messages[channelName][String(ts)] = guestMsg;
            saveData(dataJsonW);
            broadcastUpdate(["messages", channelName, String(ts)], guestMsg);
            if (uploadedFile) {
                try {
                    const fname = uploadedFile.originalname || "file";
                    const fileBuffer = uploadedFile.buffer;
                    const targetDiscordChannel = DISCORD_CHANNEL_MAP[channelName] || logid;
                    const uploadForm = new FormData();
                    uploadForm.append(
                        "payload_json",
                        JSON.stringify({ content: `**${anonName}** (guest) uploaded a file:` })
                    );
                    uploadForm.append("files[0]", fileBuffer, {
                        filename: fname,
                        contentType: uploadedFile.mimetype || "application/octet-stream",
                    });
                    const uploadResp = await discordRequestForce({
                        method: "post",
                        url: `https://discord.com/api/v10/channels/${targetDiscordChannel}/messages`,
                        data: uploadForm,
                        headers: uploadForm.getHeaders(),
                    });
                    const discordAttachment = uploadResp?.data?.attachments?.[0];
                    const cdnUrl = discordAttachment?.url || discordAttachment?.proxy_url || null;
                    const guestUploadDiscordMsgId = uploadResp?.data?.id || null;
                    if (guestUploadDiscordMsgId) {
                        botSentDiscordIds.add(guestUploadDiscordMsgId);
                        saveBotSentDiscordIds();
                        guestMsg._discordMirrorId = guestUploadDiscordMsgId;
                    }
                    if (cdnUrl) {
                        const proxied = `/discord-media-proxy?url=${encodeURIComponent(cdnUrl)}`;
                        let attachHtml = "";
                        if (/\.(png|jpg|jpeg|gif|webp)(\?|$)/i.test(fname)) {
                            attachHtml = `<img src="${proxied}" alt="${fname}" class="chat-img" style="max-width:300px;margin-top:6px;border-radius:6px;cursor:pointer;" data-fname="${fname}">`;
                        } else if (/\.(mp4|webm|mov)(\?|$)/i.test(fname)) {
                            attachHtml = `<video src="${proxied}" controls style="max-width:300px;margin-top:6px;border-radius:6px;" data-fname="${fname}"></video>`;
                        } else if (/\.(mp3|ogg|wav|flac)(\?|$)/i.test(fname)) {
                            attachHtml = `<audio src="${proxied}" controls style="margin-top:6px;" data-fname="${fname}"></audio>`;
                        } else {
                            attachHtml = `<a href="${proxied}" target="_blank" style="color:#4fa3ff;">${fname}</a>`;
                        }
                        const existingT = guestMsg.t || "";
                        guestMsg.t = existingT ? existingT + "\n" + attachHtml : attachHtml;
                        guestMsg._attachmentUrl = cdnUrl;
                    }
                    if (!DISCORD_CHANNEL_MAP[channelName] && guestUploadDiscordMsgId) {
                        try {
                            await discordRequestForce({
                                method: "delete",
                                url: `https://discord.com/api/v10/channels/${targetDiscordChannel}/messages/${guestUploadDiscordMsgId}`,
                            });
                        } catch {}
                        guestMsg._discordMirrorId = undefined;
                    }
                    dataJsonW.messages[channelName][String(ts)] = guestMsg;
                    saveData(dataJsonW);
                    broadcastUpdate(["messages", channelName, String(ts)], guestMsg);
                } catch (err) {
                    console.error("Guest File Upload Error", err);
                } finally {
                    try { fs.unlinkSync(uploadedFile.path); } catch {}
                }
            }
            if (DISCORD_CHANNEL_MAP[channelName] && !uploadedFile) {
                (async () => {
                    try {
                        const discordMsgId = await bridgeWebsiteMsgToDiscord(
                            channelName, null,
                            `${anonName}: ${msgText}\n-# This User Is Not Logged In`,
                            null
                        );
                        if (discordMsgId) {
                            const latestData = getDataCache();
                            if (latestData?.messages?.[channelName]?.[String(ts)]) {
                                latestData.messages[channelName][String(ts)]._discordMirrorId = discordMsgId;
                                saveData(latestData);
                            }
                        }
                    } catch {}
                })();
            } else if (DISCORD_CHANNEL_MAP[channelName] && !guestMsg._discordMirrorId) {
                if (msgText) {
                    bridgeWebsiteMsgToDiscord(channelName, null, `${anonName}: ${msgText}\n-# This User Is Not Logged In`, null).catch(() => {});
                }
            }
            return res.json({ success: true });
        }
        if (!uid) return res.status(401).json({ error: "Unauthorized" });
        if (
            path.length === 3 && path[0] === "messages" &&
            value && typeof value === "object" &&
            (value.t || value.text)
        ) {
            const msgText = value.t || value.text || "";
            if (/@everyone\b/i.test(msgText) || /@here\b/i.test(msgText)) {
                return res.status(403).json({ error: "@everyone And @here Are Not Allowed." });
            }
            const dataJson = getDataCache();
            const userProfile = dataJson?.users?.[uid]?.profile || {};
            const isAdminUser = !!(
                userProfile.isOwner || userProfile.isCoOwner ||
                userProfile.isAdmin || userProfile.isHAdmin ||
                userProfile.isTester
            );
            if (!isAdminUser) {
                const now = Date.now();
                const lastSend = _msgSlowmodeStore.get(uid) || 0;
                if (now - lastSend < MSG_SLOWMODE_MS) {
                    const retryAfter = Math.ceil((MSG_SLOWMODE_MS - (now - lastSend)) / 1000);
                    return res.status(429).json({
                        error: `You Can Only Send A Message Every 3 Seconds. Try Again In ${retryAfter}s.`,
                        retryAfter
                    });
                }
                _msgSlowmodeStore.set(uid, now);
            }
        }
        const dataJson = getDataCache();
        const rules = await loadRules();
        const root = new DataSnapshot(dataJson);
        let parent = dataJson;
        for (let i = 0; i < path.length - 1; i++) parent = parent[path[i]] ||= {};
        const key = path[path.length - 1];
        const oldValue = parent[key];
        const newValue = value;
        const dataSnap = new DataSnapshot(oldValue);
        const newDataSnap = new DataSnapshot(newValue);
        const userProfile = dataJson?.users?.[uid]?.profile || {};
        const auth = { uid, ...userProfile };
        const { rule, wildcards } = getRuleForOperation(rules, path, "write");
        if (!rule || !evaluate(rule, { auth, root, data: dataSnap, newData: newDataSnap, wildcards }))
            return res.status(403).json({ error: "Write denied" });
        const validateRule = getRuleForOperation(rules, path, "validate").rule;
        if (validateRule && !evaluate(validateRule, { auth, root, data: dataSnap, newData: newDataSnap, wildcards }))
            return res.status(403).json({ error: "Validation failed" });
        parent[key] = newValue;
        saveData(dataJson);
        if (path.length >= 2 && path[0] === "pushTokens") {
            const tokenUid = path[1];
            if (!dataJson.notifications) dataJson.notifications = {};
            if (!dataJson.notifications[tokenUid]) dataJson.notifications[tokenUid] = {};
            if (!dataJson.notifications[tokenUid].tokens) dataJson.notifications[tokenUid].tokens = {};
            if (path.length === 3) {
                dataJson.notifications[tokenUid].tokens[path[2]] = newValue;
            } else if (path.length === 2 && newValue && typeof newValue === "object") {
                dataJson.notifications[tokenUid].tokens = { ...dataJson.notifications[tokenUid].tokens, ...newValue };
            }
            saveData(dataJson);
        }
        broadcastUpdate(path, newValue);
        if (
            uploadedFile &&
            path.length === 3 &&
            path[0] === "messages" &&
            newValue && typeof newValue === "object"
        ) {
            const channel = path[1];
            const msgTimestamp = String(path[2]);
            try {
                const fname = uploadedFile.originalname || "file";
                const fileBuffer = uploadedFile.buffer;
                const targetDiscordChannel = DISCORD_CHANNEL_MAP[channel] || logid;
                const uploadForm = new FormData();
                const uploaderProfile = getDataCache()?.users?.[uid]?.profile || {};
                const uploaderName = uploaderProfile.displayName || "User";
                uploadForm.append("payload_json", JSON.stringify({ content: `**${uploaderName}** Uploaded A File:` }));
                uploadForm.append("files[0]", fileBuffer, {
                    filename: fname,
                    contentType: uploadedFile.mimetype || "application/octet-stream",
                });
                const uploadResp = await discordRequestForce({
                    method: "post",
                    url: `https://discord.com/api/v10/channels/${targetDiscordChannel}/messages`,
                    data: uploadForm,
                    headers: uploadForm.getHeaders(),
                });
                const discordAttachment = uploadResp?.data?.attachments?.[0];
                const cdnUrl = discordAttachment?.url || discordAttachment?.proxy_url || null;
                const uploadedDiscordMsgId = uploadResp?.data?.id || null;
                if (cdnUrl) {
                    const proxied = `/discord-media-proxy?url=${encodeURIComponent(cdnUrl)}`;
                    let attachHtml = "";
                    if (/\.(png|jpg|jpeg|gif|webp)(\?|$)/i.test(fname)) {
                        attachHtml = `<img src="${proxied}" alt="${fname}" class="chat-img" style="max-width:300px;margin-top:6px;border-radius:6px;cursor:pointer;" data-fname="${fname}">`;
                    } else if (/\.(mp4|webm|mov)(\?|$)/i.test(fname)) {
                        attachHtml = `<video src="${proxied}" controls style="max-width:300px;margin-top:6px;border-radius:6px;" data-fname="${fname}"></video>`;
                    } else if (/\.(mp3|ogg|wav|flac)(\?|$)/i.test(fname)) {
                        attachHtml = `<audio src="${proxied}" controls style="margin-top:6px;" data-fname="${fname}"></audio>`;
                    } else {
                        attachHtml = `<a href="${proxied}" target="_blank" style="color:#4fa3ff;">${fname}</a>`;
                    }
                    const data = getDataCache();
                    if (data?.messages?.[channel]?.[msgTimestamp]) {
                        const existingT = data.messages[channel][msgTimestamp].t || "";
                        data.messages[channel][msgTimestamp].t = existingT
                            ? existingT + "\n" + attachHtml
                            : attachHtml;
                        data.messages[channel][msgTimestamp]._attachmentUrl = cdnUrl;
                        if (uploadedDiscordMsgId) {
                            botSentDiscordIds.add(uploadedDiscordMsgId);
                            saveBotSentDiscordIds();
                            data.messages[channel][msgTimestamp]._discordMirrorId = uploadedDiscordMsgId;
                        }
                        saveData(data);
                        broadcastUpdate(path, data.messages[channel][msgTimestamp]);
                    }
                }
                if (uploadedDiscordMsgId && !DISCORD_CHANNEL_MAP[channel]) {
                    try {
                        await discordRequestForce({
                            method: "delete",
                            url: `https://discord.com/api/v10/channels/${targetDiscordChannel}/messages/${uploadedDiscordMsgId}`,
                        });
                    } catch {}
                }
            } catch (e) {
                console.error("[FileUpload] Failed to upload file to Discord:", e.message);
            } finally {
                try { fs.unlinkSync(uploadedFile.path); } catch {}
            }
        }
        res.json({ success: true });
        (async () => {
            try {
                if (
                    path.length === 3 &&
                    path[0] === "messages" &&
                    newValue &&
                    typeof newValue === "object" &&
                    newValue.t &&
                    newValue.s
                ) {
                    const channel = path[1];
                    const msgTimestamp = String(path[2]);
                    if (DISCORD_CHANNEL_MAP[channel]) {
                        const latestData = getDataCache();
                        const latestEntry = latestData?.messages?.[channel]?.[msgTimestamp];
                        if (!uploadedFile || !latestEntry?._discordMirrorId) {
                            const discordMsgId = await bridgeWebsiteMsgToDiscord(
                                channel,
                                newValue.s,
                                latestEntry?.t || newValue.t,
                                newValue.r || null
                            );
                            if (discordMsgId) {
                                const data = getDataCache();
                                if (data?.messages?.[channel]?.[msgTimestamp]) {
                                    data.messages[channel][msgTimestamp]._discordMirrorId = discordMsgId;
                                    saveData(data);
                                }
                            }
                        }
                    }
                    const matches = [...(newValue.t.matchAll(/@([^\s<]+)/g))];
                    for (const [, name] of matches) {
                        if (name.toLowerCase() === "support") continue;
                        const targetUid = await getUidByDisplayNameServer(name);
                        if (targetUid && targetUid !== uid) {
                            await sendMentionNotification(targetUid, uid, channel, msgTimestamp, newValue.t);
                        }
                    }
                    if (newValue.r) {
                        const replyTargetTs = String(newValue.r);
                        const msgData = getDataCache();
                        const repliedEntry = msgData?.messages?.[channel]?.[replyTargetTs];
                        if (repliedEntry) {
                            const repliedSenderUid = repliedEntry.s || null;
                            if (repliedSenderUid && repliedSenderUid !== uid) {
                                const senderProfile = msgData?.users?.[uid]?.profile;
                                sendReplyNotification(repliedSenderUid, uid, senderProfile?.displayName || "Someone", channel, msgTimestamp, newValue.t);
                            }
                        }
                    }
                } else if (
                    path.length === 3 &&
                    path[0] === "messages" &&
                    newValue &&
                    typeof newValue === "object" &&
                    newValue.text &&
                    newValue.sender
                ) {
                    const channel = path[1];
                    const msgTimestamp = String(path[2]);
                    if (DISCORD_CHANNEL_MAP[channel]) {
                        const latestData = getDataCache();
                        const latestEntry = latestData?.messages?.[channel]?.[msgTimestamp];
                        if (!uploadedFile || !latestEntry?._discordMirrorId) {
                            const discordMsgId = await bridgeWebsiteMsgToDiscord(
                                channel,
                                newValue.sender,
                                latestEntry?.t || newValue.text,
                                newValue.reply || null
                            );
                            if (discordMsgId) {
                                const data = getDataCache();
                                if (data?.messages?.[channel]?.[msgTimestamp]) {
                                    data.messages[channel][msgTimestamp]._discordMirrorId = discordMsgId;
                                    saveData(data);
                                }
                            }
                        }
                    }
                    const matches = [...(newValue.text.matchAll(/@([^\s<]+)/g))];
                    for (const [, name] of matches) {
                        if (name.toLowerCase() === "support") continue;
                        const targetUid = await getUidByDisplayNameServer(name);
                        if (targetUid && targetUid !== uid) {
                            await sendMentionNotification(targetUid, uid, channel, msgTimestamp, newValue.text);
                        }
                    }
                    if (newValue.reply) {
                        const replyTargetTs = String(newValue.reply);
                        const msgData = getDataCache();
                        const repliedEntry = msgData?.messages?.[channel]?.[replyTargetTs];
                        if (repliedEntry) {
                            const repliedSenderUid = repliedEntry.s || repliedEntry.sender || null;
                            if (repliedSenderUid && repliedSenderUid !== uid) {
                                const senderProfile = msgData?.users?.[uid]?.profile;
                                await sendReplyNotification(repliedSenderUid, uid, senderProfile?.displayName || "Someone", channel, msgTimestamp, newValue.text);
                            }
                        }
                    }
                } else if (
                    path.length === 4 &&
                    path[0] === "messages" &&
                    (path[3] === "t" || path[3] === "text") &&
                    newValue &&
                    typeof newValue === "string"
                ) {
                    const channel = path[1];
                    const msgTs = path[2];
                    if (DISCORD_CHANNEL_MAP[channel]) {
                        await bridgeEditToDiscord(channel, msgTs, newValue, uid);
                    }
                }
                if (
                    path.length === 4 &&
                    path[0] === "private" &&
                    newValue &&
                    typeof newValue === "object" &&
                    newValue.text &&
                    newValue.sender
                ) {
                    const [uidA, uidB] = [path[1], path[2]];
                    const recipientUid = newValue.sender === uidA ? uidB : uidA;
                    if (recipientUid && recipientUid !== uid) {
                        await sendDMNotification(recipientUid, uid, newValue.text);
                    }
                }
            } catch (notifErr) {
                console.error("Post-write Notification Error:", notifErr.message || notifErr);
            }
        })();
    } catch (err) {
        console.error(err);
        res.status(401).json({ error: "Unauthorized" });
    }
});
app.put("/api/movies-json", requireAdminPassword, (req, res) => {
    const pass = req.headers["x-admin-password"];
    if (pass === process.env.DON_PASS_1) {
        return res.status(403).json({
            error: "You Are Not Allowed To Use These Services"
        });
    }
    try {
        if (typeof req.body !== "object") {
            return res.status(400).json({ error: "Invalid JSON Body" });
        }
        saveMoviesJSON(req.body);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: "Failed To Save movies.json" });
    }
});
httpServer.on("upgrade", (request, socket, head) => {
    const pathname = new URL(request.url, `http://${request.headers.host}`).pathname;
    if (
        pathname.startsWith("/socket_io_live_" + UNIQUE_SUFFIX) ||
        pathname.startsWith("/socket_io_realtime_" + UNIQUE_SUFFIX)
    ) {
        return;
    }
    wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit("connection", ws, request);
    });
});
process.on("SIGINT", () => {
    console.clear();
    console.log("\nExiting");
    process.exit(0);
});
rl.on("line", (input) => {
    const trimmed = input.trim();
    {
        switch (trimmed) {
            case "1":
                listFilesLive();
                break;
            case "2":
                deleteFilePrompt();
                break;
            case "3":
                toggleLockdown();
                break;
            case "4":
                console.log("Exiting...");
                rl.close();
                process.exit(0);
                break;
            default:
                console.log("Invalid Choice");
                mainMenu();
        }
    }
});
rl.setPrompt("> ");
wss.on("connection", async (ws, req) => {
    try {
        const url = new URL(req.url, `http://${req.headers.host}`);
        const rawToken = url.searchParams.get("token");
        const token = rawToken && rawToken !== "null" ? rawToken : null;
        const wsPath = JSON.parse(url.searchParams.get("path") || "[]");
        const limit = Number(url.searchParams.get("limit") || 50);
        let uid = null;
        if (token) {
            try {
                uid = await verifyToken(token);
            } catch {
                uid = null;
            }
        }
        const dataJson = getDataCache();
        const rules = await loadRules();
        const root = new DataSnapshot(dataJson);
        let auth = null;
        if (uid) {
            const userProfile = dataJson?.users?.[uid]?.profile || {};
            auth = { uid, ...userProfile };
        }
        let guestAllowed = false;
        if (!uid && wsPath.length >= 2 && wsPath[0] === "messages") {
            const chName = wsPath[1];
            const chData = dataJson?.channels?.[chName];
            guestAllowed = !!(chData?.guestRead);
        }
        const { rule, wildcards } = getRuleForOperation(rules, wsPath, "read");
        const rulePass = !rule || evaluate(rule, { auth, root, data: root, newData: root, wildcards });
        if (!rulePass && !guestAllowed) {
            return ws.close();
        }
        try {
            let current = dataJson;
            for (const p of wsPath) current = current?.[p];
            if (current && typeof current === "object" && !Array.isArray(current)) {
                const keys = Object.keys(current).slice(-limit);
                current = keys.reduce((acc, k) => { acc[k] = current[k]; return acc; }, {});
            }
            const filtered = filterDataByRules(current, wsPath, auth, root, rules);
            const snapshotStr = JSON.stringify(filtered);
            ws.send(snapshotStr);
            wsClients.set(ws, { uid, path: wsPath, auth, limit, lastData: snapshotStr, rules, lastPollAt: Date.now(), guestAllowed });
        } catch (e) {
            wsClients.set(ws, { uid, path: wsPath, auth, limit, lastData: null, rules, lastPollAt: 0, guestAllowed });
        }
        ws.on("close", () => {
            wsClients.delete(ws);
        });
        ws.on("error", () => {
            wsClients.delete(ws);
        });
    } catch (err) {
        console.error("WS connection error:", err);
        ws.close();
    }
});
async function bridgeDeleteToDiscord(channelName, timestamp) {
    const discordChannelId = DISCORD_CHANNEL_MAP[channelName];
    if (!discordChannelId) return;
    const data = getDataCache();
    const entry = data?.messages?.[channelName]?.[timestamp];
    if (!entry) return;
    if (!entry._discordMirrorId) return;
    if (entry.u) return;
    try {
        await discordRequestForce({
            method: "delete",
            url: `https://discord.com/api/v10/channels/${discordChannelId}/messages/${entry._discordMirrorId}`,
        });
    } catch (e) {
        console.error("Failed To Delete Discord Mirror Message:", e.message);
    }
}
async function bridgeDeleteToDiscordWithEntry(channelName, timestamp, entry) {
    const discordChannelId = DISCORD_CHANNEL_MAP[channelName];
    if (!discordChannelId) return;
    if (!entry) return;
    if (!entry._discordMirrorId) return;
    try {
        await discordRequestForce({
            method: "delete",
            url: `https://discord.com/api/v10/channels/${discordChannelId}/messages/${entry._discordMirrorId}`,
        });
    } catch (e) {
        console.error("Failed To Delete Discord Mirror Message:", e.message);
    }
}
async function bridgeEditToDiscord(channelName, timestamp, newText, senderUid) {
    const discordChannelId = DISCORD_CHANNEL_MAP[channelName];
    if (!discordChannelId) return;
    const data = getDataCache();
    const entry = data?.messages?.[channelName]?.[timestamp];
    if (!entry) return;
    if (entry.u) return;
    if (!entry._discordMirrorId) return;
    try {
        const profile = data?.users?.[senderUid]?.profile || {};
        const displayName = profile.displayName || "User";
        await discordRequestForce({
            method: "patch",
            url: `https://discord.com/api/v10/channels/${discordChannelId}/messages/${entry._discordMirrorId}`,
            data: { content: `**${displayName}**: ${newText}` },
            headers: { "Content-Type": "application/json" },
        });
    } catch (e) {
        console.error("Failed To Edit Discord Mirror Message:", e.message);
    }
}
async function bridgeWebsiteMsgToDiscord(channelName, senderUid, text, replyTimestamp) {
    const discordChannelId = DISCORD_CHANNEL_MAP[channelName];
    if (!discordChannelId) return null;
    const data = getDataCache();
    const profile = data?.users?.[senderUid]?.profile || {};
    const displayName = profile.displayName || "User";
    const content = `**${displayName}**: ${text || ""}`;
    const payload = { content };
    if (replyTimestamp) {
        const entry = data?.messages?.[channelName]?.[replyTimestamp];
        if (entry?._discordId) {
            payload.message_reference = { message_id: entry._discordId };
            payload.allowed_mentions = { replied_user: false };
        }
    }
    try {
        const resp = await discordRequestForce({
            method: "post",
            url: `https://discord.com/api/v10/channels/${discordChannelId}/messages`,
            data: payload,
            headers: { "Content-Type": "application/json" },
        });
        const discordMsgId = resp?.data?.id;
        if (discordMsgId) { botSentDiscordIds.add(discordMsgId); saveBotSentDiscordIds(); }
        return discordMsgId;
    } catch (e) {
        console.error("Failed To Bridge Message To Discord:", e.message);
        return null;
    }
}
async function cleanupAndReindexPfps() {
    const githubToken = process.env.GITHUB_TOKEN;
    const owner = "InfiniteCampus41";
    const repo = "InfiniteCampus";
    const branch = "main";
    const indexRes = await axios.get(
        `https://api.github.com/repos/${owner}/${repo}/contents/pfps/index.json`,
        { headers: { Authorization: `token ${githubToken}` } }
    );
    const indexSha = indexRes.data.sha;
    const indexJson = JSON.parse(
        Buffer.from(indexRes.data.content, "base64").toString()
    );
    const _pfpData = getDataCache();
    const _pfpUsers = _pfpData.users || {};
    const usedIndexes = new Set();
    for (const userData of Object.values(_pfpUsers)) {
        const pic = userData?.profile?.pic;
        if (typeof pic === "number") {
            usedIndexes.add(pic);
        }
    }
    const usedFiles = indexJson.filter((_, i) => usedIndexes.has(i));
    const oldToNew = {};
    let newIndex = 0;
    for (let i = 0; i < indexJson.length; i++) {
        if (usedIndexes.has(i)) {
            oldToNew[i] = newIndex;
            newIndex++;
        }
    }
    for (let i = 0; i < indexJson.length; i++) {
        if (!usedIndexes.has(i)) {
            const fileName = indexJson[i];
            const fileRes = await axios.get(
                `https://api.github.com/repos/${owner}/${repo}/contents/pfps/${fileName}`,
                { headers: { Authorization: `token ${githubToken}` } }
            );
            await axios.delete(
                `https://api.github.com/repos/${owner}/${repo}/contents/pfps/${fileName}`,
                {
                    headers: { Authorization: `token ${githubToken}` },
                    data: {
                        message: "Auto Remove Unused PFPs",
                        sha: fileRes.data.sha,
                        branch
                    }
                }
            );
        }
    }
    const newIndexJson = [];
    for (let i = 0; i < usedFiles.length; i++) {
        const oldFile = usedFiles[i];
        const ext = path.extname(oldFile);
        const newFileName = `${i + 1}${ext}`;
        newIndexJson.push(newFileName);
        if (oldFile !== newFileName) {
            const fileRes = await axios.get(
                `https://api.github.com/repos/${owner}/${repo}/contents/pfps/${oldFile}`,
                { headers: { Authorization: `token ${githubToken}` } }
            );
            await axios.put(
                `https://api.github.com/repos/${owner}/${repo}/contents/pfps/${newFileName}`,
                {
                    message: "Auto Rename PFPs",
                    content: fileRes.data.content,
                    branch
                },
                { headers: { Authorization: `token ${githubToken}` } }
            );
            await axios.delete(
                `https://api.github.com/repos/${owner}/${repo}/contents/pfps/${oldFile}`,
                {
                    headers: { Authorization: `token ${githubToken}` },
                    data: {
                        message: "Auto Remove Unused PFPs",
                        sha: fileRes.data.sha,
                        branch
                    }
                }
            );
        }
    }
    const updatedIndexContent = Buffer.from(
        JSON.stringify(newIndexJson, null, 2)
    ).toString("base64");
    await axios.put(
        `https://api.github.com/repos/${owner}/${repo}/contents/pfps/index.json`,
        {
            message: "Auto Reindex PFPs",
            content: updatedIndexContent,
            sha: indexSha,
            branch
        },
        { headers: { Authorization: `token ${githubToken}` } }
    );
    const _pfpUpdateData = getDataCache();
    let _pfpChanged = false;
    for (const [_userId, _userData] of Object.entries(_pfpUpdateData.users || {})) {
        const oldPic = _userData?.profile?.pic;
        if (typeof oldPic === "number") {
            if (oldToNew.hasOwnProperty(oldPic)) {
                _pfpUpdateData.users[_userId].profile.pic = oldToNew[oldPic];
                _pfpChanged = true;
            } else {
                delete _pfpUpdateData.users[_userId].profile.pic;
                _pfpChanged = true;
            }
        }
    }
    if (_pfpChanged) saveData(_pfpUpdateData);
}
async function createVM(apiKey) {
    const now = Date.now();
    if (now - lastCreateTime < CREATE_COOLDOWN) {
        await new Promise(r => setTimeout(r, CREATE_COOLDOWN));
    }
    lastCreateTime = Date.now();
    const resp = await axios.post(
        "https://engine.hyperbeam.com/v0/vm",
        {},
        {
            headers: {
                Authorization: `Bearer ${apiKey}`,
            },
        }
    );
    return resp.data;
}
async function discordRequest({ method = "get", url, headers = {}, data = null, params = null }) {
    if (DISCORD_DISABLED) {
        return Promise.reject(new Error("Discord disabled"));
    }
    const config = {
        method,
        url,
        headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}`, ...headers },
        data,
        params,
        maxBodyLength: Infinity,
    };
    return enqueueDiscordRequest(config);
}
async function discordRequestForce({ method = "get", url, headers = {}, data = null, params = null }) {
    const config = {
        method,
        url,
        headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}`, ...headers },
        data,
        params,
        maxBodyLength: Infinity,
    };
    return enqueueDiscordRequest(config);
}
async function findMovieId(movieName) {
    try {
        const searchRes = await fetch(
            `https://api.themoviedb.org/3/search/movie?api_key=${TMDB_API_KEY}&query=${encodeURIComponent(movieName)}`
        );
        const searchData = await searchRes.json();
        if (!searchData.results || searchData.results.length === 0) {
            return { id: null, cover: null, rating: null };
        }
        const bestMatch = searchData.results[0];
        let coverUrl = null;
        if (bestMatch.poster_path) {
            coverUrl = `https://image.tmdb.org/t/p/w500${bestMatch.poster_path}`;
        }
        let rating = null;
        if (bestMatch.vote_average) {
            rating = Math.round((bestMatch.vote_average / 2) * 10) / 10;
        }
        return {
            id: bestMatch.id,
            cover: coverUrl,
            rating: rating
        };
    } catch (err) {
        console.error(err);
        return { id: null, cover: null, rating: null };
    }
}
async function finishAccept(movieName) {
    const msgId = applicantMessages.get(movieName);
    if (!msgId) return;
    applicantMessages.delete(movieName);
    if (acceptIntervals.has(movieName)) {
        clearInterval(acceptIntervals.get(movieName));
        acceptIntervals.delete(movieName);
    }
    const embed = {
        title: `${movieName} Has Been Accepted`,
        color: 0x2ecc71
    };
    updateApply(movieName, {
        status: "Done",
        percent: 100,
        eta: 0
    });
    const report = loadReportJSON();
    const day = new Date().getDate().toString();
    if (!report.report[day]) report.report[day] = {};
    const movieFiles = fs.readdirSync(MOVIES_DIR).filter(f => f.endsWith('.mp4'));
    report.report[day]["movies"] = { count: movieFiles.length };
    for (const dayKey in report.report) {
        if (report.report[dayKey]["submitted-movies"]) {
            for (const submittedId in report.report[dayKey]["submitted-movies"]) {
                if (submittedId !== "count" && submittedId === movieName) {
                    report.report[dayKey]["submitted-movies"][submittedId].accepted = "true";
                }
            }
        }
    }
    saveReportJSON(report);
    await discordRequest({
        method: "patch",
        url: `https://discord.com/api/v10/channels/${logid}/messages/${msgId}`,
        data: { embeds: [embed], components: [] },
        headers: { "Content-Type": "application/json" }
    });
    setTimeout(() => {
        clearCompletedApplies();
        acceptStatus.delete(movieName);
        pinnedAcceptLines.delete(movieName);
        if (acceptIntervals.has(movieName)) {
            clearInterval(acceptIntervals.get(movieName));
            acceptIntervals.delete(movieName);
        }
    }, 5000);
}
async function finishReject(movieName) {
    const msgId = applicantMessages.get(movieName);
    if (!msgId) return;
    applicantMessages.delete(movieName);
    if (acceptIntervals.has(movieName)) {
        clearInterval(acceptIntervals.get(movieName));
        acceptIntervals.delete(movieName);
    }
    const embed = {
        title: `${movieName} Has Been Rejected`,
        color: 0xe74c3c
    };
    updateApply(movieName, {
        status: "Rejected"
    });
    const report = loadReportJSON();
    for (const dayKey in report.report) {
        if (report.report[dayKey]["submitted-movies"]) {
            for (const submittedId in report.report[dayKey]["submitted-movies"]) {
                if (submittedId !== "count" && submittedId === movieName) {
                    report.report[dayKey]["submitted-movies"][submittedId].accepted = "false";
                }
            }
        }
    }
    saveReportJSON(report);
    try {
        await discordRequest({
            method: "patch",
            url: `https://discord.com/api/v10/channels/${logid}/messages/${msgId}`,
            data: { embeds: [embed], components: [] },
            headers: { "Content-Type": "application/json" }
        });
    } catch (e) {
    }
    deleteApply(movieName);
}
async function getUidByDisplayNameServer(displayName) {
    const data = getDataCache();
    const clean = (displayName || "").replace(/ 💎/g, "").toLowerCase();
    for (const [uid, userData] of Object.entries(data.users || {})) {
        const dn = userData?.profile?.displayName;
        if (dn && dn.replace(/ 💎/g, "").toLowerCase() === clean) return uid;
    }
    return null;
}
async function _getPushTokensForUser(uid) {
    const data = getDataCache();
    const tokenMap = data?.notifications?.[uid]?.tokens || {};
    return Object.keys(tokenMap);
}
async function grantPremium(uid, amount) {
    try {
        if (amount >= 200) {
            const expireDate = new Date();
            expireDate.setMonth(expireDate.getMonth() + 3);
            const updates = {
                preExpire: expireDate.getTime()
            };
            if (amount >= 1000) updates.premium3 = true;
            else if (amount >= 500) updates.premium2 = true;
            else if (amount >= 200) updates.premium1 = true;
            updateDataPath(`users/${uid}/profile`, updates);
        } else {
            updateDataPath(`users/${uid}/profile`, { isDonater: true });
        }
        const profile = readDataPath(`users/${uid}/profile`);
        const displayName = profile?.displayName || "User";
        const userEmail = readDataPath(`users/${uid}/settings/userEmail`);
        const tierLabel = getPremiumTierLabel(profile);
        const expireMs = profile?.preExpire ? profile.preExpire - Date.now() : null;
        const expireStr = expireMs ? formatExpire(expireMs) : "3 months";
        const amountStr = `$${(amount / 100).toFixed(2)}`;
        if (amount >= 200 && userEmail) {
            await sendTemplatedEmail("premium_purchased", userEmail, "Your Infinite Campus Premium Is Now Active!", {
                DISPLAYNAME: displayName,
                TIER: tierLabel,
                EXPIRE: expireStr,
                EMAIL: userEmail,
                UID: uid,
                AMOUNT: amountStr
            }).catch(err => console.error("[Email] premium_purchased failed:", err.message));
        }
        if (amount >= 1000) {
            await sendDiscordEmbedPre({
                title: "Premium T3 Purchased",
                color: 0xFF0000,
                fields: [
                    { name: "Name", value: displayName, inline: false },
                    { name: "Amount", value: amountStr, inline: true },
                    { name: "Duration", value: "3 Months", inline: true }
                ],
                timestamp: new Date().toISOString()
            });
            console.log("Premium T3 Granted:", uid);
        } else if (amount >= 500) {
            await sendDiscordEmbedPre({
                title: "Premium T2 Purchased",
                color: 0xFFA500,
                fields: [
                    { name: "Name", value: displayName, inline: false },
                    { name: "Amount", value: amountStr, inline: true },
                    { name: "Duration", value: "3 Months", inline: true }
                ],
                timestamp: new Date().toISOString()
            });
            console.log("Premium T2 Granted:", uid);
        } else if (amount >= 200) {
            await sendDiscordEmbedPre({
                title: "Premium T1 Purchased",
                color: 0xFFFF00,
                fields: [
                    { name: "Name", value: displayName, inline: false },
                    { name: "Amount", value: amountStr, inline: true },
                    { name: "Duration", value: "3 Months", inline: true }
                ],
                timestamp: new Date().toISOString()
            });
            console.log("Premium T1 Granted:", uid);
        } else {
            await sendDiscordEmbedPre({
                title: "New Donation",
                color: 0x00E5FF,
                fields: [
                    { name: "Name", value: displayName, inline: false },
                    { name: "Amount", value: amountStr, inline: true }
                ],
                timestamp: new Date().toISOString()
            });
        }
    } catch (err) {
        console.error("Premium Grant Error:", err, uid);
    }
}
async function loadData() {
    const data = await fs.promises.readFile("./data.json", "utf-8");
    return JSON.parse(data);
}
async function loadRules() {
    const data = await fs.promises.readFile("./rules.json", "utf-8");
    return JSON.parse(data).rules;
}
async function runFfmpegWithProgress(socket, workId, statusKey, filenameLabel, inputPath, outputPath, knownDuration, ffmpegArgs, humanLabel ) {
    return new Promise((resolve, reject) => {
        socket.emit("jobLog", { filename: filenameLabel, text: `${humanLabel} — Starting` });
        const startTime = Date.now();
        const args = [...ffmpegArgs, "-progress", "pipe:1", "-nostats"];
        const ff = spawn("ffmpeg", args, { stdio: ["ignore", "pipe", "pipe"] });
        let stdoutBuf = "";
        let stderrBuf = "";
        ff.stdout.on("data", (chunk) => {
            stdoutBuf += chunk.toString();
            const lines = stdoutBuf.split(/\r?\n/);
            stdoutBuf = lines.pop() || "";
            lines.forEach((line) => {
                const [key, value] = line.split("=");
                if (!key || !value) return;
                if (key === "out_time_ms" && knownDuration > 0) {
                    const outMs = parseInt(value, 10);
                    const elapsedSec = (Date.now() - startTime) / 1000;
                    const doneSec = outMs / 1000000;
                    const percent = Math.min(100, (doneSec / knownDuration) * 100);
                    const speed = doneSec / elapsedSec || 0;
                    const remainingSec = speed > 0
                        ? Math.max(0, (knownDuration - doneSec) / speed)
                        : 0;
                    acceptStatus.set(statusKey, {
                        status: "running",
                        percent: Math.round(percent),
                        remainingSec: Math.round(remainingSec),
                        message: humanLabel,
                        updated: Date.now()
                    });
                    updateApply(statusKey, {
                        status: humanLabel,
                        percent: Math.round(percent),
                        eta: Math.round(remainingSec)
                    });
                    const pct = Math.round(percent);
                    const etaText = formatETA(remainingSec);
                    pinnedAcceptLines.set(statusKey, `${statusKey}: ${humanLabel} ${pct}% ETA ${etaText}`);
                    renderPinnedAccept();
                    socket.emit("jobProgress", {
                        workId,
                        filename: filenameLabel,
                        percent: pct,
                        remainingSec: Math.round(remainingSec),
                        text: `${humanLabel}: ${pct}% — ETA ${etaText}`
                    });
                }
            });
        });
        ff.stderr.on("data", (chunk) => {
            stderrBuf += chunk.toString();
            if (stderrBuf.length > 2000) stderrBuf = stderrBuf.slice(-2000);
        });
        ff.on("close", (code) => {
            if (code === 0) {
                pinnedAcceptLines.delete(statusKey);
                renderPinnedAccept();
                socket.emit("jobProgress", {
                    workId,
                    filename: filenameLabel,
                    percent: 100,
                    remainingSec: 0,
                    text: `${humanLabel} Complete`
                });
                resolve();
            } else {
                reject(new Error(`Ffmpeg Failed With Code ${code}`));
            }
        });
    });
}
async function runInitialDiscordSync() {
    for (const [channelName, discordChannelId] of Object.entries(DISCORD_CHANNEL_MAP)) {
        try {
            await syncDiscordHistory(channelName, discordChannelId);
        } catch (e) {
            console.error(`Sync Failed For ${channelName}:`, e.message);
        }
    }
}
async function sendApplicantEmbed(movieName, watchLink, acceptLink, rejectLink, fileSize) {
    const formattedSize = formatSize(fileSize);
    const embed = {
        title: "New Applicant",
        description: `Movie: **${movieName}**\nSize: **${formattedSize}**`,
        color: 0x8cbe37
    };
    const payload = {
        embeds: [embed],
        components: [
            {
                type: 1,
                components: [
                    {
                        type: 2,
                        style: 5,
                        label: "Watch",
                        url: watchLink
                    },
                    {
                        type: 2,
                        style: 5,
                        label: "Accept",
                        url: acceptLink
                    },
                    {
                        type: 2,
                        style: 5,
                        label: "Reject",
                        url: rejectLink
                    }
                ]
            }
        ]
    };
    const msg = await discordRequest({
        method: "post",
        url: `https://discord.com/api/v10/channels/${logid}/messages`,
        data: payload,
        headers: { "Content-Type": "application/json" }
    });
    applicantMessages.set(movieName, msg.data.id);
    updateApply(movieName, {
        messageId: msg.data.id
    });    
    return msg.data.id;
}
async function sendDiscordEmbed(embed) {
    return discordRequestForce({
        method: "post",
        url: `https://discord.com/api/v10/channels/1460415667520933939/messages`,
        data: { embeds: [embed] },
        headers: { "Content-Type": "application/json", "Authorization": `Bot ${DISCORD_BOT_TOKEN}` }
    });
}
async function sendDiscordEmbedPre(embed) {
    return discordRequestForce({
        method: "post",
        url: `https://discord.com/api/v10/channels/1469744070162120899/messages`,
        data: { embeds: [embed] },
        headers: { "Content-Type": "application/json", "Authorization": `Bot ${DISCORD_BOT_TOKEN}` }
    });
}
async function sendDMNotification(targetUid, senderUid, text) {
    try {
        const tokens = await _getPushTokensForUser(targetUid);
        if (!tokens.length) return;
        const data = getDataCache();
        const senderProfile = data?.users?.[senderUid]?.profile || {};
        const senderIsOwner = !!(senderProfile.isOwner || senderProfile.isCoOwner);
        const settings = data?.notifications?.[targetUid]?.settings || {};
        if (settings.dms === false && !senderIsOwner) return;
        const senderName = data?.users?.[senderUid]?.profile?.displayName || "Someone";
        const preview = (text || "").substring(0, 80);
        const url = `/InfiniteChatters.html?dm=${encodeURIComponent(senderUid)}`;
        await admin.messaging().sendEachForMulticast({
            tokens,
            notification: {
                title: `DM From ${senderName}`,
                body:  preview
            },
            data: { type: "dm", url, senderUid },
            webpush: { fcmOptions: { link: url } }
        });
        logEvent("notifications", {
            id: `dm_${Date.now()}`,
            data: { type: "dm", to: targetUid, from: senderUid }
        });
    } catch (e) {
        console.error("DM Notification Error:", e.message || e);
    }
}
async function sendMentionNotification(targetUid, senderUid, channel, msgId, text) {
    try {
        const tokens = await _getPushTokensForUser(targetUid);
        if (!tokens.length) return;
        const data = getDataCache();
        const senderProfile = data?.users?.[senderUid]?.profile || {};
        const senderIsOwner = !!(senderProfile.isOwner || senderProfile.isCoOwner);
        const settings = data?.notifications?.[targetUid]?.settings || {};
        if (settings.mentions === false && !senderIsOwner) return;
        const senderName = data?.users?.[senderUid]?.profile?.displayName || "Someone";
        const preview = (text || "").substring(0, 80);
        const url = `/InfiniteChatters.html?channel=${encodeURIComponent(channel || "General")}#msg-${msgId}`;
        await admin.messaging().sendEachForMulticast({
            tokens,
            notification: {
                title: `${senderName} Mentioned You`,
                body:  preview
            },
            data: { type: "mention", url, channel: channel || "", msgId: String(msgId) },
            webpush: { fcmOptions: { link: url } }
        });
        logEvent("notifications", {
            id: `mention_${Date.now()}`,
            data: { type: "mention", to: targetUid, from: senderUid, channel: channel || "", msgId: String(msgId) }
        });
    } catch (e) {
        console.error("Mention Notification Error:", e.message || e);
    }
}
async function sendReactionNotification(targetUid, reactorUid, emoji, channel, msgId) {
    try {
        const tokens = await _getPushTokensForUser(targetUid);
        if (!tokens.length) return;
        const data = getDataCache();
        const reactorProfile = data?.users?.[reactorUid]?.profile || {};
        const senderIsOwner = !!(reactorProfile.isOwner || reactorProfile.isCoOwner);
        const settings = data?.notifications?.[targetUid]?.settings || {};
        if (settings.reactions === false && !senderIsOwner) return;
        const reactorName = data?.users?.[reactorUid]?.profile?.displayName || "Someone";
        const url = `/InfiniteChatters.html?channel=${encodeURIComponent(channel || "General")}#msg-${msgId}`;
        await admin.messaging().sendEachForMulticast({
            tokens,
            notification: {
                title: "New Reaction",
                body:  `${reactorName} Reacted ${emoji} To Your Message`
            },
            data: { type: "reaction", url, channel: channel || "", msgId: String(msgId) },
            webpush: { fcmOptions: { link: url } }
        });
        logEvent("notifications", {
            id: `reaction_${Date.now()}`,
            data: { type: "reaction", to: targetUid, from: reactorUid, emoji, channel: channel || "", msgId: String(msgId) }
        });
    } catch (e) {
        console.error("Reaction Notification Error:", e.message || e);
    }
}
async function sendReplyNotification(targetUid, senderUid, senderDisplayName, channel, msgId, text) {
    try {
        if (targetUid && targetUid === senderUid) return;
        const tokens = await _getPushTokensForUser(targetUid);
        if (!tokens.length) return;
        const data = getDataCache();
        const settings = data?.notifications?.[targetUid]?.settings || {};
        if (settings.replies === false) return;
        const preview = (text || "").substring(0, 80);
        const url = `/InfiniteChatters.html?channel=${encodeURIComponent(channel || "General")}#msg-${msgId}`;
        const title = senderDisplayName
            ? `${senderDisplayName} Replied To You`
            : "Someone Replied To You";
        await admin.messaging().sendEachForMulticast({
            tokens,
            notification: { title, body: preview },
            data: { type: "reply", url, channel: channel || "", msgId: String(msgId) },
            webpush: { fcmOptions: { link: url } }
        });
        logEvent("notifications", {
            id: `reply_${Date.now()}`,
            data: { type: "reply", to: targetUid, from: senderUid || senderDisplayName, channel: channel || "", msgId: String(msgId) }
        });
    } catch (e) {
        console.error("Reply Notification Error:", e.message || e);
    }
}
/**
 * @param {string} templateName
 * @param {string} toEmail
 * @param {string} subject
 * @param {Object} vars
 */
async function sendTemplatedEmail(templateName, toEmail, subject, vars = {}) {
    try {
        const html = renderTemplate(templateName, vars);
        const result = await resend.emails.send({
            from: "support@infinitecampus.xyz",
            to: toEmail,
            subject,
            html
        });
        console.log(`[Email] Sent "${templateName}" To ${toEmail} — ID: ${result.data?.id}`);
        return result;
    } catch (err) {
        console.error(`[Email] Failed To Send "${templateName}" To ${toEmail}:`, err.message);
        throw err;
    }
}
async function sendVerificationNotification(uid, displayName) {
    const _svData = getDataCache();
    const tokens = [];
    for (const [user, userData] of Object.entries(_svData.users || {})) {
        const profile = userData?.profile || {};
        if (profile.isOwner || profile.isTester || profile.isCoOwner || profile.isDev) {
            const pushTokens = _svData?.notifications?.[user]?.tokens || {};
            for (const tokenKey of Object.keys(pushTokens)) {
                tokens.push(tokenKey);
            }
        }
    }
    if (tokens.length === 0) {
        console.log("No Admin Tokens Found.");
        return;
    }
    const verifyUrl = `/verify-user?uid=${encodeURIComponent(uid)}`;
    const message = {
        data: {
            type: "verifyUser",
            uid: uid,
            url: `/InfiniteAdmins.html?chat=true`,
            verifyUrl
        },
        notification: {
            title: "A New User Has Signed Up!",
            body: `User ${displayName} Is Awaiting Verification`
        },
        tokens: tokens,
        webpush: {
            fcmOptions: { link: `/InfiniteAdmins.html?chat=true` },
            notification: {
                title: "A New User Has Signed Up!",
                body: `User ${displayName} Is Awaiting Verification`,
                actions: [
                    { action: "verify", title: "Verify User" },
                    { action: "dismiss", title: "Dismiss" }
                ],
                data: { type: "verifyUser", uid, verifyUrl }
            }
        }
    };
    const response = await admin.messaging().sendEachForMulticast(message);
    console.log("Verification Notification Sent.");
    console.log("Success:", response.successCount);
    logEvent("notifications", {
        id: `verify_${uid}_${Date.now()}`,
        data: { type: "verifyUser", uid, displayName }
    });
}
async function startAcceptProcess(movieName) {
    updateApply(movieName, {
        status: "Copying",
        percent: 0,
        eta: null
    });
    const oldMsgId = applicantMessages.get(movieName);
    if (oldMsgId) {
        await discordRequest({
            method: "delete",
            url: `https://discord.com/api/v10/channels/${logid}/messages/${oldMsgId}`
        });
    }
    const embed = {
        title: `ACCEPTING: ${movieName}`,
        color: 0x8cbe37,
        fields: [
            { name: "Status", value: "Scaling/Copying", inline: false },
            { name: "Percent", value: "0%", inline: false },
            { name: "Time Left", value: "Calculating...", inline: false }
        ]
    };
    const msg = await discordRequest({
        method: "post",
        url: `https://discord.com/api/v10/channels/${logid}/messages`,
        data: { embeds: [embed] },
        headers: { "Content-Type": "application/json" }
    });
    const messageId = msg.data.id;
    applicantMessages.set(movieName, messageId);
    if (acceptIntervals.has(movieName)) clearInterval(acceptIntervals.get(movieName));
    const interval = setInterval(async () => {
        const status = acceptStatus.get(movieName);
        if (status) {
            updateApply(movieName, {
                status: status.message || "Processing",
                percent: Math.round(status.percent ?? 0),
                eta: status.remainingSec ?? 0
            });
        }
        if (!status) return;
        const updatedEmbed = {
            title: `ACCEPTING: ${movieName}`,
            color: 0xf1c40f,
            fields: [
        { name: "Status", value: status.message || "Processing" },
        { name: "Percent", value: `${status.percent ?? 0}%` },
        { name: "Time Left", value: formatETA(status.remainingSec ?? 0) }
        ]
        };
        try {
            await discordRequest({
                method: "patch",
                url: `https://discord.com/api/v10/channels/${logid}/messages/${messageId}`,
                data: { embeds: [updatedEmbed] },
                headers: { "Content-Type": "application/json" }
            });
        } catch (err) {
            console.error("Discord Error:", err.response?.data || err.message);
        }
    }, 5000);
    acceptIntervals.set(movieName, interval);
    setInterval(() => {
        for (const [movie, ivl] of acceptIntervals) {
            if (!acceptStatus.has(movie)) {
                clearInterval(ivl);
                acceptIntervals.delete(movie);
            }
        }
    }, 60000);
}
async function syncDiscordHistory(channelName, discordChannelId) {
    if (!discordChannelId) return;
    const data = getDataCache();
    if (!data.messages) data.messages = {};
    if (!data.messages[channelName]) data.messages[channelName] = {};
    const existing = data.messages[channelName];
    const existingTs = new Set(Object.keys(existing).map(Number));
    for (const [ts, entry] of Object.entries(existing)) {
        if (entry?._discordId) {
            discordMsgIdToTimestamp[entry._discordId] = {
                channel: channelName,
                timestamp: Number(ts)
            };
        }
    }
    const state = discordBridgeState[channelName] || {};
    if (state.synced) return;
    console.log(`[DiscordBridge] Syncing history for #${channelName}`);
    let lastId = null;
    let totalNew = 0;
    let fetchMore = true;
    while (fetchMore) {
        await new Promise(r => setTimeout(r, 300));
        let response;
        try {
            response = await discordRequestForce({
                method: "get",
                url: `https://discord.com/api/v10/channels/${discordChannelId}/messages`,
                params: lastId ? { limit: 100, before: lastId } : { limit: 100 }
            });
        } catch (e) {
            console.error(`[DiscordBridge] History fetch error for ${channelName}:`, e.message);
            break;
        }
        const messages = response.data;
        if (!messages?.length) break;
        for (const discordMsg of messages) {
            const ts = discordMsgToTimestamp(discordMsg.id);
            if (existingTs.has(ts)) {
                discordMsgIdToTimestamp[discordMsg.id] = {
                    channel: channelName,
                    timestamp: ts
                };
                continue;
            }
            if (!discordMsg.content && !discordMsg.embeds?.length && !discordMsg.attachments?.length) {
                continue;
            }
            const content = discordMsg.content || "";
            const attachments = discordMsg.attachments || [];
            let attachmentHtml = "";
            for (const att of attachments) {
                const attUrl = att.proxy_url || att.url || "";
                if (!attUrl) continue;
                const proxied = `/discord-media-proxy?url=${encodeURIComponent(attUrl)}`;
                const isImage = /\.(png|jpg|jpeg|gif|webp)(\?|$)/i.test(att.filename || attUrl);
                const isVideo = /\.(mp4|webm|mov)(\?|$)/i.test(att.filename || attUrl);
                const isAudio = /\.(mp3|ogg|wav|flac)(\?|$)/i.test(att.filename || attUrl);
                if (isImage) {
                    attachmentHtml += `<img src="${proxied}" alt="${att.filename || 'image'}" class="chat-img" style="max-width:300px;margin-top:6px;border-radius:6px;cursor:pointer;">`;
                } else if (isVideo) {
                    attachmentHtml += `<video src="${proxied}" controls style="max-width:300px;margin-top:6px;border-radius:6px;" data-fname="${att.filename}" || 'video'"></video>`;
                } else if (isAudio) {
                    attachmentHtml += `<audio src="${proxied}" controls style="margin-top:6px;" data-fname="${att.filename}" || 'audio'"></audio>`;
                } else {
                    attachmentHtml += `<br><a href="${proxied}" target="_blank" style="color:#4fa3ff;">${att.filename || 'Download File'}</a>`;
                }
            }
            let embedHtml = "";
            for (const embed of (discordMsg.embeds || [])) {
                embedHtml += serializeDiscordEmbed(embed);
            }
            const fullContent = content
                + (attachmentHtml ? (content ? "\n" + attachmentHtml : attachmentHtml) : "")
                + (embedHtml ? "\n" + embedHtml : "");
            if (!fullContent) continue;
            const user = discordMsg.author;
            const userId = user?.id;
            let avatarUrl;
            if (user?.avatar) {
                const ext = user.avatar.startsWith("a_") ? "gif" : "png";
                avatarUrl = `https://cdn.discordapp.com/avatars/${userId}/${user.avatar}.${ext}?size=128`;
            } else {
                const defaultIndex = Number(BigInt(userId) >> 22n) % 6;
                avatarUrl = `https://cdn.discordapp.com/embed/avatars/${defaultIndex}.png`;
            }
            const entry = {
                u: user?.username || "Unknown",
                a: `/discord-avatar-proxy?url=${encodeURIComponent(avatarUrl)}`,
                t: fullContent,
                _discordId: discordMsg.id
            };
            if (discordMsg.referenced_message) {
                entry.r = discordMsgToTimestamp(discordMsg.referenced_message.id);
            }
            if (discordMsg.edited_timestamp) {
                entry.e = "edited";
            }
            data.messages[channelName][String(ts)] = entry;
            discordMsgIdToTimestamp[discordMsg.id] = {
                channel: channelName,
                timestamp: ts
            };
            existingTs.add(ts);
            totalNew++;
        }
        if (messages.length < 100) {
            fetchMore = false;
        } else {
            lastId = messages[messages.length - 1].id;
        }
    }
    const sorted = Object.fromEntries(
        Object.entries(data.messages[channelName])
            .sort((a, b) => Number(a[0]) - Number(b[0]))
    );
    data.messages[channelName] = sorted;
    _dataCache = data;
    if (totalNew > 0) {
        fs.writeFileSync("./data.json", JSON.stringify(data, null, 2));
        console.log(`Synced ${totalNew} New Messages For #${channelName}`);
    } else {
        console.log(`No New Messages For #${channelName}`);
    }
    discordBridgeState[channelName] = { synced: true };
}
async function verifyFirebaseToken(req, res, next) {
    const header = req.headers.authorization || "";
    const token = header.split("Bearer ")[1];
    if (!token) {
        return res.status(401).json({ error: "No Token Provided" });
    }
    try {
        const decoded = await admin.auth().verifyIdToken(token);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ error: "Invalid Token" });
    }
}
async function verifyToken(reqOrToken) {
    let token;
    if (typeof reqOrToken === "string") {
        token = reqOrToken;
    } else if (reqOrToken?.headers?.authorization) {
        const header = reqOrToken.headers.authorization;
        if (!header.startsWith("Bearer ")) throw new Error("Missing token");
        token = header.split("Bearer ")[1];
    } else if (reqOrToken?.body?.token) {
        token = reqOrToken.body.token;
    } else {
        throw new Error("Missing token");
    }
    const decoded = await admin.auth().verifyIdToken(token);
    return decoded.uid;
}
async function watchForNewUsers() {
    const _initData = getDataCache();
    for (const userId of Object.keys(_initData.users || {})) {
        seenUsers.add(userId);
    }
    setInterval(async () => {
        invalidateDataCache();
        const _wuData = getDataCache();
        for (const [child, userData] of Object.entries(_wuData.users || {})) {
            if (!seenUsers.has(child)) {
                seenUsers.add(child);
                const profile = userData?.profile || {};
                const displayName = profile?.displayName || "Unknown";
                const verified = profile?.verified || false;
                if (!verified) {
                    console.log(`New Unverified User Detected: ${displayName}`);
                    await sendVerificationNotification(child, displayName);
                }
            }
        }
    }, 5000);
}
function archiveReport() {
    const now = new Date();
    const monthNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    const prevMonth = new Date(now.getFullYear(), now.getMonth() - 1, 1);
    const month = monthNames[prevMonth.getMonth()];
    const year = prevMonth.getFullYear();
    const archiveName = `${month}${year}report.json`;
    ensureArchiveDir();
    if (fs.existsSync(REPORT_JSON)) {
        const archivePath = path.join(ARCHIVE_DIR, archiveName);
        fs.copyFileSync(REPORT_JSON, archivePath);
        console.log(`Report archived as ${archiveName}`);
    }
    saveReportJSON({ report: {} });
}
function broadcastUpdate(changedPath, newValue) {
    for (const [ws, clientInfo] of wsClients.entries()) {
        if (ws.readyState !== ws.OPEN) continue;
        if (!pathsMatch(clientInfo.path, changedPath)) continue;
        try {
            const dataJson = getDataCache();
            const root = new DataSnapshot(dataJson);
            let current = dataJson;
            for (const p of clientInfo.path) current = current?.[p];
            if (current && typeof current === "object" && !Array.isArray(current)) {
                const keys = Object.keys(current).slice(-clientInfo.limit);
                current = keys.reduce((acc, k) => { acc[k] = current[k]; return acc; }, {});
            }
            const filtered = filterDataByRules(current, clientInfo.path, clientInfo.auth, root, clientInfo.rules);
            const snapshotStr = JSON.stringify(filtered);
            ws.send(snapshotStr);
            clientInfo.lastData = snapshotStr;
        } catch (e) {
            console.error("WS broadcastUpdate error:", e);
        }
    }
}
function _checkRateLimit(identifier, endpoint) {
    if (!RATE_LIMIT_ENABLED) return null;
    const cfg = RATE_LIMITS[endpoint] || RATE_LIMITS.default;
    const key = `${identifier}:${endpoint}`;
    const now = Date.now();
    let entry = _rateLimitStore.get(key);
    if (!entry || now >= entry.resetAt) {
        entry = { count: 0, resetAt: now + cfg.window };
        _rateLimitStore.set(key, entry);
    }
    entry.count++;
    if (entry.count > cfg.max) {
        const retryAfter = Math.ceil((entry.resetAt - now) / 1000);
        return { retryAfter, max: cfg.max, endpoint };
    }
    return null;
}
function cleanupLogsIfNeeded() {
    const CLEAR_DAY = parseInt(process.env.CLEAR_LOG_DAY || "1");
    const today = new Date().getDate();
    if (today === CLEAR_DAY && alreadyCleared === false) {
        saveAccLogs({});
        console.log("acclogs.json Cleared For Monthly Reset");
        alreadyCleared = true;
    } else if (alreadyCleared === true && today != CLEAR_DAY) {
        alreadyCleared = false;
    }
}
function clearCompletedApplies() {
    try {
        let data = {};
        if (fs.existsSync(APPLY_JSON)) {
            data = JSON.parse(fs.readFileSync(APPLY_JSON, "utf8"));
        }
        for (const movie in data) {
            if (data[movie]?.status === "Completed") {
                delete data[movie];
            }
        }
        fs.writeFileSync(APPLY_JSON, JSON.stringify(data, null, 2));
    } catch (err) {
        console.error("Failed To Clear Completed Applies:", err);
    }
}
function deleteApply(movieName) {
    const data = loadApplyJSON();
    delete data[movieName];
    saveApplyJSON(data);
}
function deleteFilePrompt() {
    const files = fs.readdirSync(UPLOADS_DIR).filter((f) => fs.statSync(path.join(UPLOADS_DIR, f)).isFile());
    if (files.length === 0) return console.log("No Files To Delete."), mainMenu();
    console.log("\nAvailable Files:");
    files.forEach((f, i) => console.log(`${i + 1}. ${f}`));
    rl.question("Enter Number To Delete: ", (num) => {
        const idx = parseInt(num) - 1;
        if (!isNaN(idx) && files[idx]) {
            fs.unlinkSync(path.join(UPLOADS_DIR, files[idx]));
            console.log(`Deleted ${files[idx]}`);
        }
        mainMenu();
    });
}
function discordMsgToTimestamp(snowflakeId) {
    return Number((BigInt(snowflakeId) >> 22n) + 1420070400000n);
}
function discordMsgToWebsite(discordMsg) {
    const ts = discordMsgToTimestamp(discordMsg.id);
    const avatarHash = discordMsg.author?.avatar;
    const userId = discordMsg.author?.id;
    const avatarUrl = avatarHash
        ? `https://cdn.discordapp.com/avatars/${userId}/${avatarHash}.png?size=64`
        : `https://cdn.discordapp.com/embed/avatars/0.png`;
    const proxiedAvatar = `/discord-avatar-proxy?url=${encodeURIComponent(avatarUrl)}`;
    const entry = {
        u: discordMsg.author?.username || "Unknown",
        a: proxiedAvatar,
        t: discordMsg.content || "",
    };
    if (discordMsg.referenced_message) {
        const refTs = discordMsgToTimestamp(discordMsg.referenced_message.id);
        if (refTs) entry.r = refTs;
    }
    return { ts, entry };
}
function enqueueDiscordRequest(axiosConfig) {
    return new Promise((resolve, reject) => {
        const now = Date.now();
        while (discordQueue.length &&
               now - discordQueue[0].createdAt > DISCORD_QUEUE_TTL) {
            discordQueue.shift();
        }
        if (discordQueue.length > MAX_DISCORD_QUEUE) {
            return reject(new Error("Discord Queue Full"));
        }
        discordQueue.push({
            axiosConfig,
            resolve,
            reject,
            createdAt: now
        });
    });
}
function ensureArchiveDir() {
    if (!fs.existsSync(ARCHIVE_DIR)) {
        fs.mkdirSync(ARCHIVE_DIR, { recursive: true });
    }
}
function evaluate(rule, context) {
    try {
        const fn = new Function(
            "auth",
            "root",
            "data",
            "newData",
            "now",
            ...Object.keys(context.wildcards),
            `return (${rule});`
        );
        return fn(
            context.auth,
            context.root,
            context.data,
            context.newData,
            Date.now(),
            ...Object.values(context.wildcards)
        );
    } catch (err) {
        console.error("Rule error:", err);
        return false;
    }
}
function filterDataByRules(data, pathParts, auth, root, rules) {
    if (data == null) return data;
    const { rule, wildcards } = getRuleForOperation(rules, pathParts, "read");
    const dataSnap = new DataSnapshot(data);
    let allowed = true;
    if (rule) {
        allowed = evaluate(rule, {
            auth,
            root,
            data: dataSnap,
            newData: dataSnap,
            wildcards
        });
    }
    if (typeof data !== "object") {
        return allowed ? data : undefined;
    }
    const result = Array.isArray(data) ? [] : {};
    for (const key in data) {
        const filteredChild = filterDataByRules(
            data[key],
            [...pathParts, key],
            auth,
            root,
            rules
        );
        if (filteredChild !== undefined) {
            result[key] = filteredChild;
        }
    }
    if (allowed) return result;
    if (Object.keys(result).length > 0) return result;
    return undefined;
}
function folderSizeBytes(folder) {
    const files = fs.existsSync(folder) ? fs.readdirSync(folder) : [];
    return files.reduce((sum, f) => {
        try {
            const stats = fs.statSync(path.join(folder, f));
            return sum + (stats.isFile() ? stats.size : 0);
        } catch (e) {
            return sum;
        }
    }, 0);
}
function formatBytes(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
    return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}
function formatETA(seconds) {
    seconds = Math.max(0, Math.floor(seconds));
    const days = Math.floor(seconds / 86400);
    seconds %= 86400;
    const hours = Math.floor(seconds / 3600);
    seconds %= 3600;
    const minutes = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return [
        days ? `${days}d` : null,
        (hours || days) ? `${hours}h` : null,
        (minutes || hours || days) ? `${minutes}m` : null,
        `${secs}s`
    ].filter(Boolean).join(" ");
}
function formatSize(bytes) {
    if (!bytes) return "0 MB";
    const mb = bytes / (1024 * 1024);
    if (mb < 1024) {
        return mb.toFixed(2) + " MB";
    }
    const gb = mb / 1024;
    return gb.toFixed(2) + " GB";
}
function formatTime(timestamp) {
    const date = new Date(timestamp);
    let hours = date.getHours();
    const minutes = date.getMinutes().toString().padStart(2, '0');
    const ampm = hours >= 12 ? 'PM' : 'AM';
    hours = hours % 12;
    hours = hours ? hours : 12;
    return `${hours}:${minutes} ${ampm}`;
}
function formatTimes(date) {
    return date.toLocaleString("en-US", {
        hour12: true
    });
}
function getDataCache() {
    if (_dataCache === null) {
        _dataCache = JSON.parse(fs.readFileSync("./data.json", "utf-8"));
    }
    return _dataCache;
}
function getIP(req) {
    return req.headers["x-forwarded-for"]?.split(",")[0] || req.socket?.remoteAddress || "unknown";
}
function getNextOrder(moviesJson) {
    const orders = Object.values(moviesJson).map(m => m.order);
    if (orders.length === 0) return 1;
    return Math.max(...orders) + 1;
}
function getRuleForOperation(rules, pathParts, type) {
    let current = rules;
    let lastRule = null;
    let wildcards = {};
    for (const part of pathParts) {
        if (current["." + type] !== undefined) lastRule = current["." + type];
        if (current[part]) current = current[part];
        else {
            const wildcardKey = Object.keys(current).find((k) => k.startsWith("$"));
            if (wildcardKey) {
                wildcards[wildcardKey] = part;
                current = current[wildcardKey];
            } else break;
        }
    }
    if (current?.["." + type] !== undefined) lastRule = current["." + type];
    return { rule: lastRule, wildcards };
}
function invalidateDataCache() {
    _dataCache = null;
}
function listFilesLive() {
    if (_listFilesInterval) clearInterval(_listFilesInterval);
    const renderList = () => {
        const files = fs.readdirSync(UPLOADS_DIR).filter((f) => fs.statSync(path.join(UPLOADS_DIR, f)).isFile());
        const lines = [];
        lines.push(`LIVE FILE LIST (${files.length} Files)`);
        lines.push("───────────────────────────────────────────────────────────────────────");
        if (uploadLogs.length > 0) {
            lines.push("Recent Upload Logs:");
            const lastUploadLogs = uploadLogs.slice(-10);
            for (const l of lastUploadLogs) lines.push("  " + l.message);
            lines.push("───────────────────────────────────────────────────────────────────────");
        }
        if (activeLinks.length > 0) {
            lines.push("Download Links:");
            const lastLinks = activeLinks.slice(-10);
            for (const l of lastLinks) lines.push("  " + l.url);
            lines.push("───────────────────────────────────────────────────────────────────────");
        }
        if (rateLimitLogs.length > 0) {
            lines.push("Rate-Limit / Queue Logs:");
            const lastRateLogs = rateLimitLogs.slice(-10);
            for (const l of lastRateLogs) lines.push("  " + l.message);
            lines.push("───────────────────────────────────────────────────────────────────────");
        }
        if (files.length === 0) {
            lines.push("No Files Uploaded.");
        } else {
            lines.push(" # | File Name                     | Size     | Age(s) | Deletes In(s)");
            lines.push("───┼───────────────────────────────┼──────────┼────────┼──────────────");
            files.forEach((file, i) => {
                let stats;
                try {
                    stats = fs.statSync(path.join(UPLOADS_DIR, file));
                } catch {
                    return null;
                }
                const age = Math.floor((Date.now() - stats.birthtimeMs) / 1000);
                const remain = Math.max(0, Math.floor((AUTO_DELETE_MS - (Date.now() - stats.birthtimeMs)) / 1000));
                const size = formatBytes(stats.size).padEnd(8);
                const name = file.length > 30 ? file.slice(0, 27) + ".." : file.padEnd(30);
                lines.push(`${String(i + 1).padEnd(2)} | ${name} | ${size} | ${String(age).padEnd(6)} | ${remain}`);
            });
        }
        lines.push("───────────────────────────────────────────────────────────────────────");
        lines.push("Type A File Number To Get A Download Link,");
        lines.push("Type DELETE # To Delete A File,");
        lines.push("Type MENU To Return To The Main Menu.");
        renderScreen(lines);
    };
    _listFilesInterval = setInterval(renderList, 1000);
    renderList();
}
function listMovies() {
    const moviesJson = loadMoviesJSON();
    const files = fs.readdirSync(MOVIES_DIR).filter((f) => {
        return path.extname(f).toLowerCase() === ".mp4";
    });
    let list = files.map((f) => {
        const stats = fs.statSync(path.join(MOVIES_DIR, f));
        const name = path.parse(f).name;
        return {
            file: f,
            name,
            size: stats.size,
            mtime: stats.mtime,
            humanSize: formatBytes(stats.size),
            order: moviesJson[f]?.order ?? 99999999,
            uploadedBy: moviesJson[f]?.uploadedBy || "User",
            db_id: moviesJson[f]?.db_id || null,
            cover: moviesJson[f]?.cover || null,
            rating: moviesJson[f]?.rating || null
        };
    });
    list.sort((a, b) => a.order - b.order);
    return list;
}
function loadAccLogs() {
    return JSON.parse(fs.readFileSync(ACCLOGS_PATH, "utf8") || "{}");
}
function loadApplyJSON() {
    let data = {};
    if (fs.existsSync(APPLY_JSON)) {
        try {
            data = JSON.parse(fs.readFileSync(APPLY_JSON, "utf8"));
        } catch {
            data = {};
        }
    }
    const files = new Set(
        fs.readdirSync(APPLY_DIR).filter(f => !f.endsWith(".json"))
    );
    let changed = false;
    for (const movieName of Object.keys(data)) {
        if (!files.has(movieName)) {
            delete data[movieName];
            changed = true;
        }
    }
    if (changed) {
        fs.writeFileSync(APPLY_JSON, JSON.stringify(data, null, 2));
    }
    return data;
}
function loadBotSentDiscordIds() {
    try {
        if (fs.existsSync(DISCORD_IDS_PATH)) {
            const parsed = JSON.parse(fs.readFileSync(DISCORD_IDS_PATH, "utf-8"));
            if (Array.isArray(parsed)) return new Set(parsed);
        }
    } catch (e) { console.warn("Failed To Load discordids.json:", e.message); }
    return new Set();
}
function loadDataSync() {
    return getDataCache();
}
function loadMoviesJSON() {
    if (!fs.existsSync(MOVIES_JSON)) return {};
    try {
        return JSON.parse(fs.readFileSync(MOVIES_JSON, "utf8"));
    } catch {
        return {};
    }
}
function loadReportJSON() {
    if (!fs.existsSync(REPORT_JSON)) {
        return { report: {} };
    }
    try {
        return JSON.parse(fs.readFileSync(REPORT_JSON, "utf8"));
    } catch {
        return { report: {} };
    }
}
function logEvent(eventType, eventData) {
    const now = new Date();
    const day = now.getDate().toString();
    const report = loadReportJSON();
    if (!report.report[day]) {
        report.report[day] = {};
    }
    if (!report.report[day][eventType]) {
        report.report[day][eventType] = { count: 0 };
    }
    report.report[day][eventType].count++;
    if (eventData.id) {
        report.report[day][eventType][eventData.id] = {
            time: formatTimes(now),
            ...eventData.data
        };
    }
    saveReportJSON(report);
}
function mainMenu() {
    if (_listFilesInterval) {
        clearInterval(_listFilesInterval);
        _listFilesInterval = null;
    }
    console.log("\n FILE SERVER MENU");
    console.log("1  Files");
    console.log("2  Delete A File");
    console.log("3  Lockdown (Currently: " + (LOCKDOWN ? "ON" : "OFF") + ")");
    console.log("4  Exit");
    rl.question("Choose An Option: ", (a) => {
        switch (a.trim()) {
            case "1":
                listFilesLive();
                break;
            case "2":
                deleteFilePrompt();
                break;
            case "3":
                toggleLockdown();
                break;
            case "4":
                console.log("Exiting...");
                rl.close();
                console.clear();
                process.exit(0);
            default:
                console.log("Invalid Choice");
                mainMenu();
        }
    });
}
function markExpiredTokens() {
    const logs = loadAccLogs();
    const now = Date.now();
    for (const uid in logs) {
        const entry = logs[uid];
        if (entry.expiresRaw && now > entry.expiresRaw) {
            entry.expires = "expired";
        }
    }
    saveAccLogs(logs);
}
function pathsMatch(clientPath, updatePath) {
    if (updatePath.length < clientPath.length) return false;
    for (let i = 0; i < clientPath.length; i++) {
        if (clientPath[i] !== updatePath[i]) return false;
    }
    return true;
}
function pruneOldLogs() {
    const cutoff = Date.now() - 5 * 60 * 1000;
    activeLinks = activeLinks.filter((l) => l.ts >= cutoff);
}
function pushUploadLog(filename, sizeBytes) {
    const now = Date.now();
    const sizeStr = formatBytes(sizeBytes);
    const msg = `${filename} Was Uploaded At ${new Date(now)
        .toISOString()
        .replace("T", " ")
        .split(".")[0]} With A Size Of ${sizeStr}.`;
    discordRequestForce({
        method: "post",
        url: `https://discord.com/api/v10/channels/${logid}/messages`,
        data: {
            content: `File ${filename} Was Uploaded With A Size Of ${sizeStr}.`
        },
        headers: { "Content-Type": "application/json" }
    });
    uploadLogs.push({ message: msg, ts: now });
    if (uploadLogs.length > 1000) {
        uploadLogs.shift();
    }
    console.log(msg);
}
function rateLimit(endpoint) {
    return async (req, res, next) => {
        if (!RATE_LIMIT_ENABLED) return next();
        let identifier = null;
        const header = req.headers.authorization;
        if (header?.startsWith("Bearer ")) {
            try {
                identifier = (await admin.auth().verifyIdToken(header.split("Bearer ")[1])).uid;
            } catch { }
        }
        if (!identifier) identifier = getIP(req);
        const hit = _checkRateLimit(identifier, endpoint);
        if (hit) {
            const msg = `[RateLimit] ${endpoint} exceeded by ${identifier} (${hit.max}/window)`;
            rateLimitLogs.push({ message: msg, ts: Date.now() });
            if (rateLimitLogs.length > 2000) rateLimitLogs.shift();
            return res.status(429).json({
                error: `Rate limit exceeded for "${endpoint}". Try again in ${hit.retryAfter}s.`,
                retryAfter: hit.retryAfter
            });
        }
        next();
    };
}
function readDataPath(pathStr) {
    const data = getDataCache();
    const keys = pathStr.split("/").filter(Boolean);
    let cur = data;
    for (const k of keys) {
        if (cur == null) return null;
        cur = cur[k];
    }
    return cur ?? null;
}
function renderPinnedAccept() {
    if (pinnedAcceptLines.size === 0) return;
    const currentInput = rl.line || "";
    const prompt = rl.getPrompt() || "> ";
    readline.cursorTo(process.stdout, 0, 0);
    readline.clearLine(process.stdout, 0);
    process.stdout.write([...pinnedAcceptLines.values()].join(" | "));
    readline.cursorTo(process.stdout, prompt.length + currentInput.length);
}
function renderScreen(lines) {
    const currentInput = rl.line || "";
    const prompt = rl.getPrompt() || "> ";
    readline.cursorTo(process.stdout, 0, 0);
    readline.clearScreenDown(process.stdout);
    for (const ln of lines) process.stdout.write(ln + "\n");
    process.stdout.write(prompt + currentInput);
    readline.cursorTo(process.stdout, prompt.length + currentInput.length);
}
function requireAdminForChannel(req, res, allowedSet, channelId) {
    if (allowedSet.has(channelId)) return true;
    const pass = req.headers["x-admin-password"];
    const validPasswords = [
        process.env.ADMIN_PASSWORD,
        process.env.ADMIN_PASSWORD_2,
        process.env.DON_PASS_1,
        process.env.YOYOMASTER,
        process.env.NITRIX67
    ];
    if (!pass || !validPasswords.includes(pass)) {
        res.status(403).json({ error: "Forbidden: Admin Password Required For This Channel" });
        return false;
    }
    return true;
}
function requireAdminPassword(req, res, next) {
    const adminRoutes = [
        `/hyperadminvm`,
        `/api/movies-json`,
        `/api/list_apply_${UNIQUE_SUFFIX}`,
        `/delete/${UNIQUE_SUFFIX}`,
        `/api/delete_apply_${UNIQUE_SUFFIX}`
    ];
    const isAdminPrefix = req.path.startsWith("/admin");
    const isAdminExact = adminRoutes.includes(req.path);
    if (isAdminPrefix || isAdminExact) {
        const pass = req.headers["x-admin-password"];
        const validPasswords = [
            process.env.ADMIN_PASSWORD,
            process.env.ADMIN_PASSWORD_2,
            process.env.DON_PASS_1,
            process.env.YOYOMASTER,
            process.env.NITRIX67
        ];
        if (!pass || !validPasswords.includes(pass)) {
            return res.status(401).json({ error: "Unauthorized: Invalid Password" });
        }
    }
    next();
}
function resolveAnonName(sessionToken) {
    if (!sessionToken) return "Anonymous";
    const s = anonSessions.get(sessionToken);
    return s?.name || "Anonymous";
}
function restoreApplicantMessages() {
    const data = loadApplyJSON();
    for (const movie in data) {
        if (data[movie].messageId) {
            applicantMessages.set(movie, data[movie].messageId);
        }
    }
}
function safeName(original) {
    const ext = path.extname(original).toLowerCase();
    const base = sanitize(path.parse(original).name).replace(/\s+/g, "_") || "file";
    const ts = Date.now();
    return `${base}_${ts}${ext || ".mp4"}`;
}
function saveAccLogs(data) {
    fs.writeFileSync(ACCLOGS_PATH, JSON.stringify(data, null, 2));
}
function saveApplyJSON(data) {
    fs.writeFileSync(APPLY_JSON, JSON.stringify(data, null, 4));
}
function saveBotSentDiscordIds() {
    try {
        fs.writeFileSync(DISCORD_IDS_PATH, JSON.stringify([...botSentDiscordIds], null, 2));
    } catch (e) { console.error("Failed To Save discordids.json:", e.message); }
}
function saveData(data) {
    _dataCache = data;
    fs.writeFileSync("./data.json", JSON.stringify(data, null, 2));
}
function saveDiscordChannelMap() {
    try {
        fs.writeFileSync(DISCORD_CHANNEL_MAP_PATH, JSON.stringify(DISCORD_CHANNEL_MAP, null, 2));
    } catch (e) { console.error("Failed To Save Channel Map:", e.message); }
}
function saveMoviesJSON(data) {
    fs.writeFileSync(MOVIES_JSON, JSON.stringify(data, null, 4));
}
function saveReportJSON(data) {
    fs.writeFileSync(REPORT_JSON, JSON.stringify(data, null, 2));
}
function scheduleDailyClear() {
    const now = new Date();
    const next = new Date();
    next.setHours(21, 1, 0, 0);
    if (next <= now) {
        next.setDate(next.getDate() + 1);
    }
    const msUntil = next - now;
    setTimeout(() => {
        uploadLogs.length = 0;
        rateLimitLogs.length = 0;
        activeLinks.length = 0;
        console.log("LOGS CLEARED");
        scheduleDailyClear();
    }, msUntil);
}
function serializeDiscordEmbed(embed) {
    if (!embed) return "";
    const color = embed.color ? `#${embed.color.toString(16).padStart(6, "0")}` : "#5865F2";
    let html = `<div class="discord-embed" style="border-left:4px solid ${color};background:rgba(30,31,34,0.9);border-radius:4px;padding:10px 14px;margin-top:6px;max-width:400px;display:inline-block;">`;
    if (embed.author) {
        const authorIcon = embed.author.proxy_icon_url || embed.author.icon_url || embed.author.iconURL || "";
        const authorName = embed.author.name || embed.author.text || "";
        const authorUrl = embed.author.url || "";
        html += `<div style="display:flex;align-items:center;gap:6px;margin-bottom:6px;">`;
        if (authorIcon) html += `<img src="${authorIcon}" style="width:20px;height:20px;border-radius:50%;object-fit:cover;" onerror="this.style.display='none'">`;
        if (authorUrl) html += `<a href="${authorUrl}" target="_blank" style="color:#ddd;font-size:0.82em;font-weight:600;text-decoration:none;">${authorName}</a>`;
        else html += `<span style="color:#ddd;font-size:0.82em;font-weight:600;">${authorName}</span>`;
        html += `</div>`;
    }
    if (embed.title || embed.url) {
        const title = embed.title || "";
        const url = embed.url || "";
        if (url) html += `<div style="margin-bottom:4px;"><a href="${url}" target="_blank" style="color:#4fa3ff;font-weight:700;text-decoration:none;">${title}</a></div>`;
        else if (title) html += `<div style="color:#fff;font-weight:700;margin-bottom:4px;">${title}</div>`;
    }
    if (embed.description) {
        const desc = embed.description.replace(/\n/g, "<br>").replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>").replace(/\*(.*?)\*/g, "<em>$1</em>");
        html += `<div style="color:#ddd;font-size:0.9em;margin-bottom:6px;">${desc}</div>`;
    }
    const fields = embed.fields || [];
    if (fields.length > 0) {
        html += `<div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:4px;">`;
        for (const field of fields) {
            const fieldVal = (field.value || "").replace(/\n/g, "<br>").replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>");
            html += `<div style="${field.inline ? "min-width:100px;flex:1;" : "width:100%;"}">`;
            html += `<div style="color:#bbb;font-size:0.78em;font-weight:700;margin-bottom:2px;">${field.name || ""}</div>`;
            html += `<div style="color:#ddd;font-size:0.85em;">${fieldVal}</div>`;
            html += `</div>`;
        }
        html += `</div>`;
    }
    const imageUrl = embed.image?.proxy_url || embed.image?.url || embed.image?.proxyURL || "";
    if (imageUrl) {
        html += `<img src="${imageUrl}" style="max-width:360px;margin-top:8px;border-radius:4px;display:block;" onerror="this.style.display='none'">`;
    }
    const thumbUrl = embed.thumbnail?.proxy_url || embed.thumbnail?.url || embed.thumbnail?.proxyURL || "";
    if (thumbUrl && !imageUrl) {
        html += `<img src="${thumbUrl}" style="max-width:80px;float:right;border-radius:4px;margin-left:8px;" onerror="this.style.display='none'">`;
    }
    if (embed.footer) {
        const footerText = embed.footer.text || "";
        const footerIcon = embed.footer.proxy_icon_url || embed.footer.icon_url || embed.footer.iconURL || "";
        html += `<div style="display:flex;align-items:center;gap:5px;margin-top:8px;">`;
        if (footerIcon) html += `<img src="${footerIcon}" style="width:16px;height:16px;border-radius:50%;object-fit:cover;" onerror="this.style.display='none'">`;
        html += `<span style="color:#999;font-size:0.75em;">${footerText}</span>`;
        if (embed.timestamp) {
            const ts = new Date(embed.timestamp).toLocaleDateString();
            html += `<span style="color:#999;font-size:0.75em;"> • ${ts}</span>`;
        }
        html += `</div>`;
    }
    html += `</div>`;
    const b64 = Buffer.from(html).toString("base64");
    return `<discord-embed-b64 data="${b64}"></discord-embed-b64>`;
}
function setupSocketHandlers(ioInstance, label) {
    ioInstance.on("connection", (socket) => {
        console.log(`${label} Admin Socket Connected:`, socket.id);
        socket.on("acceptApplicant", (payload) => {
            const { filename, targetName } = payload;
            const safeFile = path.basename(filename);
            const srcPath = path.join(APPLY_DIR, safeFile);
            if (!fs.existsSync(srcPath)) {
                return socket.emit("jobError", { filename: safeFile, message: "Source File Not Found" });
            }
            const existing = acceptStatus.get(safeFile);
            if (existing && existing.status === "running" || existing?.status === "copying" || existing?.status === "scaling") {
                return socket.emit("jobError", { filename: safeFile, message: "This File Is Already Being Processed" });
            }
            const workId = `${safeFile}_${Date.now()}`;
            socket.emit("jobStarted", { filename: safeFile, workId });
            acceptStatus.set(safeFile, {
                status: "running",
                percent: 0,
                remainingSec: null,
                message: "Job Started",
                updated: Date.now()
            });
            (async () => {
                await startAcceptProcess(safeFile);
                try {
                    socket.emit("jobLog", { filename: safeFile, text: "Probing File For Duration..." });
                    const probeCmd = `ffprobe -v quiet -print_format json -show_format "${srcPath.replace(/"/g, '\\"')}"`;
                    let probeOut = "";
                    try {
                        const { stdout } = await execProm(probeCmd);
                        probeOut = stdout;
                    } catch (e) {
                        probeOut = "";
                    }
                    let duration = 0;
                    try {
                        const probeJson = probeOut ? JSON.parse(probeOut) : null;
                        duration = parseFloat((probeJson && probeJson.format && probeJson.format.duration) || 0);
                    } catch (e) {
                        console.warn("Ffprobe Parse Failed", e);
                        duration = 0;
                    }
                    socket.emit("jobLog", { filename: safeFile, text: `Duration: ${duration ? duration.toFixed(2) + "s" : "unknown"}` });
                    const baseTarget = sanitize((targetName && targetName.trim()) ? targetName.replace(/\s+/g, "_") : path.parse(safeFile).name);
                    const copyName = `${baseTarget}_${Date.now()}_copy.mp4`;
                    const scaledName = `${baseTarget}_${Date.now()}_360.mp4`;
                    const copyPath = path.join(APPLY_DIR, copyName);
                    const scaledPathTemp = path.join(APPLY_DIR, scaledName);
                    acceptStatus.set(safeFile, {
                        status: "copying",
                        percent: 0,
                        remainingSec: null,
                        message: "Copying Container",
                        updated: Date.now()
                    });
                    await runFfmpegWithProgress(socket, workId, safeFile, safeFile, srcPath, copyPath, duration, ["-y", "-i", srcPath, "-c", "copy", copyPath], "Copying Container" );
                    try { fs.unlinkSync(srcPath); socket.emit("jobLog", { filename: safeFile, text: "Deleted Original" }); } catch (e) { socket.emit("jobLog", { filename: safeFile, text: "Could Not Delete Original (Non-Fatal)." }); }
                    await new Promise(r => setTimeout(r, 500));
                    acceptStatus.set(safeFile, {
                        status: "scaling",
                        percent: 0,
                        remainingSec: null,
                        message: "Scaling",
                        updated: Date.now()
                    });
                    await runFfmpegWithProgress(socket, workId, safeFile, copyName, copyPath, scaledPathTemp, duration, ["-y", "-i", copyPath, "-vf", "scale=640:360:force_original_aspect_ratio=decrease,pad=640:360:(ow-iw)/2:(oh-ih)/2", "-c:v", "libx264", "-crf", "23", "-preset", "veryfast", "-c:a", "copy", scaledPathTemp], "Scaling to 640x360" );
                    try { fs.unlinkSync(copyPath); socket.emit("jobLog", { filename: safeFile, text: "Deleted Intermediate Copy." }); } catch (e) {}
                    const finalFileName = `${baseTarget}.mp4`;
                    const destination = path.join(MOVIES_DIR, finalFileName);
                    let finalDest = destination;
                    let counter = 1;
                    while (fs.existsSync(finalDest)) {
                        finalDest = path.join(MOVIES_DIR, `${baseTarget}_${counter}.mp4`);
                        counter++;
                    }
                    fs.renameSync(scaledPathTemp, finalDest);
                    const moviesJson = loadMoviesJSON();
                    const baseName = path.basename(finalDest);
                    let uploaderUid = null;
                    try {
                        const metaPath = path.join(APPLY_DIR, safeFile + ".json");
                        if (fs.existsSync(metaPath)) {
                            const meta = JSON.parse(fs.readFileSync(metaPath));
                            uploaderUid = meta.uid || meta.uploadedBy || null;
                            fs.unlinkSync(metaPath);
                        }
                        if (uploaderUid && uploaderUid !== "unknown") {
                            try {
                                updateDataPath(`users/${uploaderUid}/profile`, { isUploader: true });
                            } catch (err) {
                                console.error("Failed To Grant Uploader Role:", err);
                            }
                            try {
                                const currentUploads = readDataPath(`users/${uploaderUid}/profile/uploads`);
                                const newUploads = (typeof currentUploads === "number" ? currentUploads : 0) + 1;
                                updateDataPath(`users/${uploaderUid}/profile`, { uploads: newUploads });
                            } catch (err) {
                                console.error("Failed To Increment Upload Count:", err);
                            }
                        }
                    } catch (e) {
                        console.error("Failed To Load Uploader Metadata");
                    }
                    const idBasename = path.basename(finalDest, ".mp4");
                    const cleanName = idBasename.replace(/_\d+$/, "");
                    const tmdbData = await findMovieId(cleanName);
                    if (!moviesJson[baseName]) {
                        moviesJson[baseName] = {
                            order: getNextOrder(moviesJson),
                            uploadedBy: uploaderUid,
                            db_id: tmdbData.id || null,
                            cover: tmdbData.cover || null,
                            rating: tmdbData.rating || null
                        };
                        saveMoviesJSON(moviesJson);
                    }
                    acceptStatus.set(safeFile, {
                        status: "completed",
                        percent: 100,
                        remainingSec: 0,
                        message: "Completed",
                        updated: Date.now()
                    });
                    socket.emit("jobDone", { filename: safeFile, finalName: path.basename(finalDest) });
                    await finishAccept(safeFile);
                } catch (err) {
                    pinnedAcceptLines.set(safeFile, `ACCEPT FAILED: ${safeFile}`);
                    renderPinnedAccept();
                    setTimeout(() => {
                        pinnedAcceptLines.delete(safeFile);
                        renderPinnedAccept();
                    }, 5000);
                    acceptStatus.set(safeFile, {
                        status: "error",
                        percent: 0,
                        remainingSec: null,
                        message: err.message || "Unknown Error",
                        updated: Date.now()
                    });
                    console.error("Accept Failed", err);
                    socket.emit("jobError", { filename: safeFile, message: err.message || String(err) });
                }
            })();
        });
    });
}
function startDiscordGateway() {
    if (!DISCORD_BOT_TOKEN || Object.keys(DISCORD_CHANNEL_MAP).length === 0) return;
    const discordIdToChannelName = {};
    for (const [name, id] of Object.entries(DISCORD_CHANNEL_MAP)) {
        discordIdToChannelName[id] = name;
    }
    const watchedChannelIds = new Set(Object.values(DISCORD_CHANNEL_MAP));
    async function connect() {
        if (discordGatewayWs) {
            try { discordGatewayWs.close(); } catch {}
            discordGatewayWs = null;
        }
        if (gatewayHeartbeatInterval) { clearInterval(gatewayHeartbeatInterval); gatewayHeartbeatInterval = null; }
        const wsUrl = (gatewayCanResume && gatewayResumeUrl)
            ? `${gatewayResumeUrl}/?v=10&encoding=json`
            : "wss://gateway.discord.gg/?v=10&encoding=json";
        let ws;
        try {
            const { WebSocket: WsClient } = await import("ws");
            ws = new WsClient(wsUrl);
        } catch (e) {
            console.error("Failed to open gateway WebSocket:", e.message);
            scheduleGatewayReconnect(BASE_RECONNECT_DELAY);
            return;
        }
        discordGatewayWs = ws;
        ws.on("message", (raw) => {
            let payload;
            try { payload = JSON.parse(raw.toString()); } catch { return; }
            const { op, d, s, t } = payload;
            if (s != null) gatewaySeq = s;
            if (op === 10) {
                const interval = d.heartbeat_interval;
                if (gatewayHeartbeatInterval) clearInterval(gatewayHeartbeatInterval);
                const jitter = Math.floor(Math.random() * interval);
                setTimeout(() => {
                    if (ws.readyState === ws.OPEN) {
                        ws.send(JSON.stringify({ op: 1, d: gatewaySeq }));
                    }
                }, jitter);
                gatewayHeartbeatInterval = setInterval(() => {
                    if (ws.readyState === ws.OPEN) {
                        ws.send(JSON.stringify({ op: 1, d: gatewaySeq }));
                    }
                }, interval);
                if (gatewayCanResume && gatewaySessionId && gatewaySeq != null) {
                    console.log("[DiscordGateway] Sending RESUME for session:", gatewaySessionId, "seq:", gatewaySeq);
                    ws.send(JSON.stringify({
                        op: 6,
                        d: {
                            token: DISCORD_BOT_TOKEN,
                            session_id: gatewaySessionId,
                            seq: gatewaySeq
                        }
                    }));
                } else {
                    console.log("[DiscordGateway] Sending IDENTIFY");
                    ws.send(JSON.stringify({
                        op: 2,
                        d: {
                            token: DISCORD_BOT_TOKEN,
                            intents: 33281,
                            properties: {
                                os: "linux",
                                browser: "ic-bridge",
                                device: "ic-bridge"
                            }
                        }
                    }));
                }
            } else if (op === 11) {
            } else if (op === 1) {
                if (ws.readyState === ws.OPEN) {
                    ws.send(JSON.stringify({ op: 1, d: gatewaySeq }));
                }
            } else if (op === 7) {
                console.log("[DiscordGateway] Op 7 Reconnect received — will resume");
                gatewayCanResume = true;
                scheduleGatewayReconnect(1000);
            } else if (op === 9) {
                const resumable = d === true;
                console.warn("[DiscordGateway] Op 9 Invalid Session — resumable:", resumable);
                gatewayCanResume = resumable;
                if (!resumable) {
                    gatewaySessionId = null;
                    gatewaySeq = null;
                }
                scheduleGatewayReconnect(1000 + Math.floor(Math.random() * 4000));
            } else if (op === 0 && t === "READY") {
                gatewaySessionId = d.session_id;
                gatewayResumeUrl = d.resume_gateway_url || null;
                gatewayCanResume = true;
                gatewayReconnectAttempts = 0;
                console.log("[DiscordBridge] Gateway connected, session:", gatewaySessionId, "resume_url:", gatewayResumeUrl);
            } else if (op === 0 && t === "RESUMED") {
                gatewayReconnectAttempts = 0;
                console.log("[DiscordGateway] Session successfully resumed");
            } else if (op === 0 && t === "MESSAGE_CREATE") {
                if (!watchedChannelIds.has(d.channel_id)) return;
                const ALLOWED_BOT_ID = process.env.ALLOWED_BOT_ID || "YOUR_BOT_ID_HERE";
                const ALLOWED_BOT_CHANNEL_IDS = new Set(
                    (process.env.ALLOWED_BOT_CHANNEL_IDS || "").split(",").map(s => s.trim()).filter(Boolean)
                );
                if (d.author?.bot) {
                    if (d.author.id === ALLOWED_BOT_ID && ALLOWED_BOT_CHANNEL_IDS.has(d.channel_id)) {
                    } else {
                        return;
                    }
                }
                const channelName = discordIdToChannelName[d.channel_id];
                if (!channelName) return;
                const ts = discordMsgToTimestamp(d.id);
                const baseContent = (d.content || d.embeds?.[0]?.description || "")
                    .replace(/@everyone\b/gi, "@\u200beveryone")
                    .replace(/@here\b/gi, "@\u200bhere");
                const gatewayAttachments = d.attachments || [];
                let gatewayAttachmentHtml = "";
                for (const att of gatewayAttachments) {
                    const attUrl = att.proxy_url || att.url || "";
                    if (!attUrl) continue;
                    const proxied = `/discord-media-proxy?url=${encodeURIComponent(attUrl)}`;
                    const isImage = /\.(png|jpg|jpeg|gif|webp)(\?|$)/i.test(att.filename || attUrl);
                    const isVideo = /\.(mp4|webm|mov)(\?|$)/i.test(att.filename || attUrl);
                    const isAudio = /\.(mp3|ogg|wav|flac|m4a)(\?|$)/i.test(att.filename || attUrl);
                    if (isImage) {
                        gatewayAttachmentHtml += `<img src="${proxied}" alt="${att.filename || 'image'}" class="chat-img" style="max-width:300px;margin-top:6px;border-radius:6px;cursor:pointer;">`;
                    } else if (isVideo) {
                        gatewayAttachmentHtml += `<video src="${proxied}" controls style="max-width:300px;margin-top:6px;border-radius:6px;" data-fname="${att.filename}" || 'video'"></video>`;
                    } else if (isAudio) {
                        gatewayAttachmentHtml += `<audio src="${proxied}" controls style="margin-top:6px;" data-fname="${att.filename}" || 'audio'"></audio>`;
                    } else {
                        gatewayAttachmentHtml += `<br><a href="${proxied}" target="_blank" style="color:#4fa3ff;">${att.filename || 'Download File'}</a>`;
                    }
                }
                const content = baseContent
                    + (gatewayAttachmentHtml ? (baseContent ? "\n" + gatewayAttachmentHtml : gatewayAttachmentHtml) : "");
                let gatewayEmbedHtml = "";
                for (const embed of (d.embeds || [])) {
                    gatewayEmbedHtml += serializeDiscordEmbed(embed);
                }
                const fullContent = content + (gatewayEmbedHtml ? (content ? "\n" + gatewayEmbedHtml : gatewayEmbedHtml) : "");
                if (!fullContent) return;
                const avatarHash = d.author?.avatar;
                const userId = d.author?.id;
                const avatarUrl = avatarHash
                    ? `https://cdn.discordapp.com/avatars/${userId}/${avatarHash}.png?size=64`
                    : `https://cdn.discordapp.com/embed/avatars/0.png`;
                const entry = {
                    u: d.author?.username || "Unknown",
                    a: `/discord-avatar-proxy?url=${encodeURIComponent(avatarUrl)}`,
                    t: fullContent,
                    _discordId: d.id,
                };
                if (d.referenced_message) {
                    entry.r = discordMsgToTimestamp(d.referenced_message.id);
                }
                console.log(channelName);
                writeDiscordMsgToData(channelName, d.id, entry, ts);
                if (d.referenced_message) {
                    try {
                        const refTs = discordMsgToTimestamp(d.referenced_message.id);
                        const replyData = getDataCache();
                        const repliedEntry = replyData?.messages?.[channelName]?.[String(refTs)];
                        if (repliedEntry) {
                            const replierDiscordUsername = (d.author?.username || "").toLowerCase();
                            const originalSenderUid = repliedEntry.s || null;
                            if (originalSenderUid) {
                                const originalSenderProfile = replyData?.users?.[originalSenderUid]?.profile || {};
                                const linkedDiscordUsername = (originalSenderProfile.dUsername || "").toLowerCase();
                                if (linkedDiscordUsername && linkedDiscordUsername === replierDiscordUsername) {
                                } else {
                                    sendReplyNotification(
                                        originalSenderUid,
                                        null,
                                        d.author?.username || "Someone",
                                        channelName,
                                        ts,
                                        d.content || ""
                                    );
                                }
                            }
                        }
                    } catch (replyNotifErr) {
                        console.error("Discord Reply Notification Error:", replyNotifErr.message || replyNotifErr);
                    }
                }
            } else if (op === 0 && t === "MESSAGE_UPDATE") {
                if (!watchedChannelIds.has(d.channel_id)) return;
                const channelName = discordIdToChannelName[d.channel_id];
                if (!channelName) return;
                const ref = discordMsgIdToTimestamp[d.id];
                if (!ref) return;
                const data = getDataCache();
                const existing = data?.messages?.[channelName]?.[ref.timestamp];
                if (!existing || !existing.u) return;
                existing.t = d.content || existing.t;
                existing.e = "edited";
                data.messages[channelName][ref.timestamp] = existing;
                saveData(data);
                broadcastUpdate(["messages", channelName, String(ref.timestamp)], existing);
            } else if (op === 0 && t === "MESSAGE_DELETE") {
                if (!watchedChannelIds.has(d.channel_id)) return;
                const channelName = discordIdToChannelName[d.channel_id];
                if (!channelName) return;
                const ref = discordMsgIdToTimestamp[d.id];
                if (!ref) return;
                const data = getDataCache();
                if (data?.messages?.[channelName]?.[ref.timestamp]) {
                    delete data.messages[channelName][ref.timestamp];
                    saveData(data);
                    broadcastUpdate(["messages", channelName, String(ref.timestamp)], null);
                }
                delete discordMsgIdToTimestamp[d.id];
            }
        });
        ws.on("close", (code) => {
            console.warn("[DiscordGateway] Connection closed, code:", code);
            if (gatewayHeartbeatInterval) { clearInterval(gatewayHeartbeatInterval); gatewayHeartbeatInterval = null; }
            const nonResumableCodes = new Set([4004, 4010, 4011, 4012, 4013, 4014]);
            if (nonResumableCodes.has(code)) {
                console.error(`[DiscordGateway] Non-resumable Close Code ${code} — Clearing Session`);
                gatewayCanResume = false;
                gatewaySessionId = null;
                gatewaySeq = null;
            } else {
                gatewayCanResume = !!(gatewaySessionId && gatewaySeq != null);
            }
            discordGatewayActive = null;
            scheduleGatewayReconnect(5000);
        });
        ws.on("error", (e) => {
            console.error("Gateway Error:", e.message);
        });
    }
    function scheduleGatewayReconnect(baseDelay) {
        if (gatewayReconnectTimer) return;
        gatewayReconnectAttempts++;
        if (gatewayReconnectAttempts > GATEWAY_MAX_RECONNECT_ATTEMPTS) {
            console.error(`[DiscordGateway] Max reconnect attempts (${GATEWAY_MAX_RECONNECT_ATTEMPTS}) reached. Giving up to avoid token ban. Restart the server to retry.`);
            return;
        }
        const delay = Math.min(baseDelay * Math.pow(2, gatewayReconnectAttempts - 1), GATEWAY_MAX_RECONNECT_DELAY);
        console.log(`[DiscordGateway] Scheduling reconnect attempt ${gatewayReconnectAttempts}/${GATEWAY_MAX_RECONNECT_ATTEMPTS} in ${Math.round(delay / 1000)}s`);
        gatewayReconnectTimer = setTimeout(() => {
            gatewayReconnectTimer = null;
            connect();
        }, delay);
    }
    connect();
}
function toggleLockdown() {
    LOCKDOWN = !LOCKDOWN;
    console.log(LOCKDOWN ? "Uploads Locked." : "Uploads Unlocked.");
    mainMenu();
}
function updateApply(movieName, newData) {
    const data = loadApplyJSON();
    if (!data[movieName]) {
        const existingIds = Object.values(data)
            .map(v => v.id)
            .filter(id => typeof id === "number");
        const nextId = existingIds.length > 0
            ? Math.max(...existingIds) + 1
            : 1;
        data[movieName] = {
            id: nextId
        };
    }
    data[movieName] = {
        ...data[movieName],
        ...newData,
        id: data[movieName].id,
        eta: newData.eta !== undefined
            ? newData.eta
            : data[movieName].eta ?? null
    };
    fs.writeFileSync(APPLY_JSON, JSON.stringify(data, null, 2));
}
function updateDataPath(pathStr, updates) {
    const data = getDataCache();
    const keys = pathStr.split("/").filter(Boolean);
    let cur = data;
    for (let i = 0; i < keys.length - 1; i++) {
        if (!cur[keys[i]] || typeof cur[keys[i]] !== "object") cur[keys[i]] = {};
        cur = cur[keys[i]];
    }
    const last = keys[keys.length - 1];
    if (!cur[last] || typeof cur[last] !== "object") cur[last] = {};
    for (const [k, v] of Object.entries(updates)) {
        if (v === null || v === undefined) delete cur[last][k];
        else cur[last][k] = v;
    }
    saveData(data);
    return data;
}
function writeDiscordMsgToData(channelName, discordMsgId, entry, ts) {
    const data = getDataCache();
    if (!data.messages) data.messages = {};
    if (!data.messages[channelName]) data.messages[channelName] = {};
    const entryWithTs = { ...entry, timestamp: Number(ts) };
    data.messages[channelName][ts] = entryWithTs;
    saveData(data);
    discordMsgIdToTimestamp[discordMsgId] = { channel: channelName, timestamp: ts };
    broadcastUpdate(["messages", channelName, String(ts)], entryWithTs);
}
setInterval(async () => {
    let processed = 0;
    while (processed < DISCORD_RPS && discordQueue.length) {
        const item = discordQueue.shift();
        processed++;
        axios(item.axiosConfig)
        .then(item.resolve)
        .catch((err) => {
            if (err.response?.status === 429) {
                const info = `Discord 429 For ${item.axiosConfig.url} At ${new Date().toISOString()}`;
                console.log(info);
            }
            item.reject(err);
        });
    }
    if (discordQueue.length > 0 && discordQueue.length % 100 === 0) {
        const info = `Discord Queue Backing Up: ${discordQueue.length} Pending At ${new Date().toISOString()}`;
        console.log(info);
    }
}, 1000);
setInterval(() => {
    pruneOldLogs();
    clearCompletedApplies();
}, 10 * 1000);
setInterval(() => {
    const now = Date.now();
    for (const dir of STALE_CLEANUP_DIRS) {
        if (!fs.existsSync(dir)) continue;
        let entries;
        try {
            entries = fs.readdirSync(dir);
        } catch (err) {
            console.error(`Stale Cleanup: Failed To Read ${dir}:`, err.message);
            continue;
        }
        for (const entry of entries) {
            const fullPath = path.join(dir, entry);
            try {
                const stat = fs.statSync(fullPath);
                const lastModified = stat.mtimeMs;
                if (now - lastModified >= STALE_CLEANUP_MS) {
                    fs.rmSync(fullPath, { recursive: true, force: true });
                    console.log(`Stale Cleanup: Deleted ${fullPath} (Last Modified ${Math.floor((now - lastModified) / 60000)}m Ago)`);
                }
            } catch (err) {
                console.error(`Stale Cleanup: Error Processing ${fullPath}:`, err.message);
            }
        }
    }
}, STALE_CLEANUP_MS);
setInterval(() => {
    const now = Date.now();
    for (const [file, status] of acceptStatus.entries()) {
        if (status.status === "running") {
            acceptStatus.set(file, {
                ...status,
                updated: now
            });
        }
    }
    for (const [fileId, lastSeen] of tempUploadActivity.entries()) {
        if (now - lastSeen > TEMP_UPLOAD_TIMEOUT) {
            const dir = path.join(UPLOADS_TEMP_DIR, fileId);
            if (fs.existsSync(dir)) {
                fs.rmSync(dir, { recursive: true, force: true });
            }
            tempUploadActivity.delete(fileId);
        }
    }
}, 30_000);
setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of _rateLimitStore.entries()) {
        if (now >= entry.resetAt) _rateLimitStore.delete(key);
    }
}, 60_000);
setInterval(() => {
    const now = Date.now();
    const ONLINE_TIMEOUT = 2 * 60 * 1000;
    for (const [uid, lastSeen] of onlineLastSeen.entries()) {
        if (now - lastSeen > ONLINE_TIMEOUT) {
            updateDataPath(`users/${uid}/profile`, { online: null });
            onlineLastSeen.delete(uid);
        }
    }
    for (const [key,time] of tempUploadActivity) {
        if (now - time > TEMP_UPLOAD_TIMEOUT) {
            tempUploadActivity.delete(key);
        }
    }
    for (const [uid, data] of discordVerifications) {
        if (now - data.created > 10 * 60 * 1000) {
            discordVerifications.delete(uid);
        }
    }
    const now2 = new Date();
    const day = now2.getDate();
    const hour = now2.getHours();
    const minute = now2.getMinutes();
    if (day === 1 && hour === 0 && minute === 0 && alreadyArchived === false) {
        archiveReport();
        alreadyArchived = true;
    } else if (day != 1) {
        alreadyArchived = false;
    }
    cleanupLogsIfNeeded();
    markExpiredTokens();
}, 60 * 1000);
setInterval(async () => {
    try {
        const now = Date.now();
        const ONE_WEEK_MS = 7 * 24 * 60 * 60 * 1000;
        const _expData = getDataCache();
        if (!_expData.users) return;
        let _expiredCount = 0;
        for (const [_expUid, _expUserData] of Object.entries(_expData.users)) {
            const profile = _expUserData?.profile;
            if (!profile) continue;
            const hasPremium = profile.premium1 || profile.premium2 || profile.premium3;
            if (!hasPremium || !profile.preExpire) continue;
            const timeLeft = profile.preExpire - now;
            const userEmail = _expUserData?.settings?.userEmail;
            const displayName = profile.displayName || "User";
            const tierLabel = getPremiumTierLabel(profile);
            if (timeLeft > 0 && timeLeft <= ONE_WEEK_MS && !profile.premiumNoticeSent && userEmail) {
                try {
                    await sendTemplatedEmail(
                        "premium_notice",
                        userEmail,
                        "Your Infinite Campus Premium Expires Soon",
                        {
                            DISPLAYNAME: displayName,
                            TIER: tierLabel,
                            EXPIRE: formatExpire(timeLeft),
                            EMAIL: userEmail,
                            UID: _expUid
                        }
                    );
                    updateDataPath(`users/${_expUid}/profile`, {
                        [PREMIUM_NOTICE_SENT_KEY]: true
                    });
                } catch (e) {
                    console.error("[Email] premium_notice Failed For", _expUid, e.message);
                }
            }
            if (timeLeft <= 0) {
                const hadEmail = userEmail;
                const hadTier = tierLabel;
                delete profile.premium1;
                delete profile.premium2;
                delete profile.premium3;
                delete profile.preExpire;
                delete profile.premiumNoticeSent;
                _expiredCount++;
                if (hadEmail) {
                    sendTemplatedEmail("premium_expired", hadEmail, "Your Infinite Campus Premium Has Expired", {
                        DISPLAYNAME: displayName,
                        TIER: hadTier,
                        EMAIL: hadEmail,
                        UID: _expUid
                    }).catch(e => console.error("[Email] premium_expired Failed For", _expUid, e.message));
                }
            }
        }
        if (_expiredCount > 0) {
            saveData(_expData);
            console.log("Expired Premium Removed For Users:", _expiredCount);
        }
    } catch (err) {
        console.error("Premium Expiration Job Error:", err);
    }
}, 5 * 60 * 1000);
setInterval(() => {
    if (acceptStatus.size > 500) {
        acceptStatus.clear();
    }
}, 10 * 60 * 1000);
setInterval(() => {
    const now = Date.now();
    for (const [tok, s] of anonSessions) {
        if (now - s.createdAt > ANON_SESSION_TTL) anonSessions.delete(tok);
    }
}, 60 * 60 * 1000);
setInterval(async () => {
    if (wsClients.size === 0) return;
    let dataJson;
    try {
        dataJson = getDataCache();
    } catch (e) {
        return;
    }
    const root = new DataSnapshot(dataJson);
    const now = Date.now();
    for (const [ws, clientInfo] of wsClients.entries()) {
        if (ws.readyState !== ws.OPEN) continue;
        const isTypingPath = clientInfo.path.includes("typing");
        if (!isTypingPath && now - (clientInfo.lastPollAt || 0) < WS_POLL_INTERVAL_NORMAL) continue;
        clientInfo.lastPollAt = now;
        try {
            let current = dataJson;
            for (const p of clientInfo.path) current = current?.[p];
            if (current && typeof current === "object" && !Array.isArray(current)) {
                const keys = Object.keys(current).slice(-clientInfo.limit);
                current = keys.reduce((acc, k) => { acc[k] = current[k]; return acc; }, {});
            }
            const filtered = filterDataByRules(current, clientInfo.path, clientInfo.auth, root, clientInfo.rules);
            const snapshotStr = JSON.stringify(filtered);
            if (isTypingPath || snapshotStr !== clientInfo.lastData) {
                ws.send(snapshotStr);
                clientInfo.lastData = snapshotStr;
            }
        } catch (err) {
            console.error("WS Poll Error:", err);
        }
    }
}, WS_POLL_INTERVAL_TYPING);
setupSocketHandlers(ioLive, "LIVE");
setupSocketHandlers(ioRealtime, "REALTIME");
scheduleDailyClear();
restoreApplicantMessages();
watchForNewUsers();
(async () => {
    await runInitialDiscordSync();
    if (!discordGatewayActive) {
        startDiscordGateway()
        discordGatewayActive = true;
    }
})();