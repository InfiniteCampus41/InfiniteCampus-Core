import admin from "firebase-admin";
import axios from "axios";
import child_process from "child_process";
import { Client, Environment, WebhooksHelper } from "square";
import cors from "cors";
import { createServer } from "http";
import crypto from "crypto";
import dotenv from "dotenv";
import express from "express";
import fetch from "node-fetch";
import { fileURLToPath } from "url";
import FormData from "form-data";
import fs from "fs";
import multer from "multer";
import os from "os";
import path from "path";
import readline from "readline";
import sanitize from "sanitize-filename";
import { Server as IOServer } from "socket.io";
import { spawn } from "child_process";
import util from "util";
dotenv.config();
const app = express();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, uploadedby, ngrok-skip-browser-warning, x-admin-password, fileId, chunkIndex, totalChunks, filename, x-user-id, X-File-Id, X-Chunk-Number, X-Total-Chunks, X-Filename, X-User-Id");
    if (req.method === "OPTIONS") return res.sendStatus(200);
    next();
});
app.use(cors({ origin: "*", methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"], allowedHeaders: [ "Content-Type", "Authorization", "ngrok-skip-browser-warning", "x-admin-password", "fileId", "chunkIndex", "totalChunks", "filename", "x-user-id", "X-File-Id", "X-Chunk-Number", "X-Total-Chunks", "X-User-Id", "uploadedby"]}));
const SQUARE_SIGNATURE_KEY = process.env.SQUARE_WEBHOOK_SIGNATURE_KEY;
const SQUARE_WEBHOOK_URL = "https://api.infinitecampus.xyz/square-webhook";
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
                const donationRef = db.ref(`donations/amount`);
                await donationRef.transaction((current) => {
                    return (current || 0) + amountDollars;
                });
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
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
const exec = util.promisify(util.promisify ? util.promisify : (fn => fn));
const execProm = util.promisify(child_process.exec);
if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert(JSON.parse(fs.readFileSync("./admin.json"))),
        databaseURL: "https://notes-27f22-default-rtdb.firebaseio.com"
    });
}
const UNIQUE_SUFFIX = "x9a7b2";
const UPLOAD_LIMIT_MB = 100;
const UPLOADS_DIR = path.join(__dirname, "uploads");
const UPLOADS_TEMP_DIR = path.join(__dirname, "uploads_temp");
const acceptIntervals = new Map();
const acceptStatus = new Map();
const ALLOWED_EXTS = new Set([".mp4", ".mov", ".mkv", ".ts", ".webm", ".avi", ".flv", ".mpeg", ".mpg", ".m4v",]);
const ALLOWED_PFP_EXTS = new Set([".png", ".jpeg", ".jpg", ".webp", ".ico"]);
const applicantMessages = new Map();
const APPLY_DIR = path.join(__dirname, "apply");
const APPLY_JSON = path.join(__dirname, "apply.json");
const AUTO_DELETE_MS = 5 * 60 * 1000;
const AUTO_DELETE_PM_MS = 15 * 60 * 1000;
const client = new Client({
    environment: Environment.Production,
    accessToken: process.env.SQUARE_ACCESS_TOKEN,
});
const CREATE_COOLDOWN = 1500;
const creating = new Map();
const db = admin.database();
const DEFAULT_CHANNEL_ID = process.env.CHANNEL_ID;
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const discordQueue = [];
const DISCORD_QUEUE_DIR = path.join(__dirname, "discord_queue");
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
const FOLDER_LIMIT_MB = 1024;
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
const logid = "1460410323369721868";
const MAX_APPLY_BYTES = 30 * 1024 * 1024 * 1024;
const MAX_DISCORD_QUEUE = 5000;
const MAX_FILE_BYTES = 1024 * 1024 * 1024 * 30;
const MAX_SIZE_NON_PREMIUM = 100 * 1024 * 1024;
const MAX_SIZE_PREMIUM = 500 * 1024 * 1024;
const memoryUpload = multer({
    storage: multer.diskStorage({
        destination: UPLOADS_TEMP_DIR,
        filename: (req,file,cb)=>cb(null,Date.now()+"-"+file.originalname)
    })
});
const MOVIES_DIR = path.join(__dirname, "movies");
const MOVIES_JSON = path.join(__dirname, "movies.json");
const REPORT_JSON = path.join(__dirname, "report.json");
const ARCHIVE_DIR = path.join(__dirname, "archive");
const PFP_COOLDOWN_MS = 3 * 60 * 1000;
const pfpStorage = multer.memoryStorage();
const pfpUploadCooldown = new Map();
const PORT = process.env.PORT || 4000;
const QUEUE_DIR = path.join(__dirname, "queue");
const rateLimitLogs = [];
const READY_DIR = path.join(__dirname, "ready");
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
const seenUsers = new Set();
const sessions = new Map();
const storageApply = multer.diskStorage({
    destination: (req, file, cb) => cb(null, APPLY_DIR),
    filename: (req, file, cb) => cb(null, safeName(file.originalname)),
});
const tempUploadActivity = new Map();
const TEMP_UPLOAD_TIMEOUT = 3 * 60 * 60 * 1000;
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
let activeLinks = [];
let DISCORD_DISABLED = false;
let discordQueueProcessing = false;
let lastCreateTime = 0;
let liveInterval = null;
let liveMode = false;
let LOCKDOWN = false;
let pinnedAcceptLine = null;
let testEnabled = false;
let vm;
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
if (!fs.existsSync(APPLY_DIR)) fs.mkdirSync(APPLY_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_TEMP_DIR)) fs.mkdirSync(UPLOADS_TEMP_DIR, { recursive: true });
if (!fs.existsSync(MOVIES_DIR)) fs.mkdirSync(MOVIES_DIR, { recursive: true });
if (!fs.existsSync(READY_DIR)) fs.mkdirSync(READY_DIR, { recursive: true });
if (!fs.existsSync(QUEUE_DIR)) fs.mkdirSync(QUEUE_DIR, { recursive: true });
if (!fs.existsSync(DISCORD_QUEUE_DIR)) fs.mkdirSync(DISCORD_QUEUE_DIR, { recursive: true });
if (!fs.existsSync(ARCHIVE_DIR)) fs.mkdirSync(ARCHIVE_DIR, { recursive: true });
rl.setPrompt("> ");
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
function blockDiscordIfDisabled(req, res, next) {
    if (DISCORD_DISABLED) {
        return res.status(403).json({ error: "Discord integration disabled" });
    }
    next();
}
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
app.get("/api/messages", blockDiscordIfDisabled, async (req, res) => {
    let channelId = req.query.channelId || DEFAULT_CHANNEL_ID;
    const ALLOWED_CHANNELS = new Set([
        '1464689808717774970',
        '1456025656558092372',
        '1334376148087603294',
        '1334376903179767860',
        '1334377094876237918',
        '1334377158789042226',
        '1334377258609147967',
        '1018614763250520127',
        '1389334335114580229',
        '1389630067457527879',
        '1389703415810101308',
        '1392882466351616153',
        '1309160050904006696',
        '1309164699417448550',
        '1007051892821594183',
        '1086362556203028540',
        '1390991482650886215',
        '1391898825588740108',
        '1401659961880088668'
    ]);
    if (!requireAdminForChannel(req, res, ALLOWED_CHANNELS, channelId)) return;
    const allMessages = [];
    let lastId = null;
    let fetchMore = true;
    try {
        while (fetchMore) {
            const params = lastId ? { limit: 100, before: lastId } : { limit: 100 };
            const response = await discordRequest({
                method: "get",
                url: `https://discord.com/api/v10/channels/${channelId}/messages`,
                params,
            });
            const messages = response.data;
            allMessages.push(...messages);
            if (messages.length < 100) fetchMore = false;
            else {
                lastId = messages[messages.length - 1].id;
                await new Promise((resolve) => setTimeout(resolve, 250));
            }
        }
        res.json(allMessages);
    } catch (err) {
        console.error("Message Fetch Error:", err.response?.data || err.message);
        res.status(500).json({ error: "Failed To Fetch Messages" });
    }
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
        console.error(err);
        res.status(500).json({ error: "Weather Lookup Failed" });
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
app.post("/changename", verifyFirebaseToken, async (req, res) => {
    try {
        const uid = req.user.uid;
        let { displayName } = req.body;
        if (!displayName) {
            return res.statusCode(400).json({ error: "Missing Display Name"});
        }
        const testerSnap = await admin.database().ref(`users/${uid}/profile/isTester`).get();
        const ownerSnap = await admin.database().ref(`users/${uid}/profile/isOwner`).get();
        const isTester = testerSnap.exists() && testerSnap.val() === true;
        const isOwner = ownerSnap.exists() && ownerSnap.val() === true;
        if (isOwner || isTester) {
            displayName = displayName;
        } else {
            displayName = displayName.trim();
            if (displayName.length > 20) {
                return res.status(400).json({ error: "Too Many Charachters (Max 20)"})
            }
            const valid = /^[a-zA-Z0-9 _.\-!@#$%^&*()+=\[\]{};:'",<>/?\\|`~]+$/;
            if (!valid.test(displayName)) {
                return res.status(400).json({ error: "Invalid characters" });
            }
        }
        await admin.auth().updateUser(uid, {
            displayName
        });
        await admin.database().ref(`users/${uid}/profile`).update({
            displayName
        });
        res.json({ success: true, displayName });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed To Update Display Name" });
    }
});
app.post("/changebio", verifyFirebaseToken, async (req, res) => {
    try {
        const uid = req.user.uid;
        let { bio } = req.body;
        if (!bio) {
            return res.statusCode(400).json({ error: "Missing Bio"});
        }
        const testerSnap = await admin.database().ref(`users/${uid}/profile/isTester`).get();
        const ownerSnap = await admin.database().ref(`users/${uid}/profile/isOwner`).get();
        const isTester = testerSnap.exists() && testerSnap.val() === true;
        const isOwner = ownerSnap.exists() && ownerSnap.val() === true;
        if (isOwner || isTester) {
            bio = bio;
        } else {
            if (bio.length > 50) {
                return res.status(400).json({ error: "Too Many Charachters (Max 50)"})
            }
        }
        await admin.database().ref(`users/${uid}/profile`).update({
            bio
        });
        res.json({ success: true, bio });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed To Update Bio" });
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
    await admin.database()
        .ref(`users/${uid}/profile`)
        .update({ dUsername: verify.username });
    discordVerifications.delete(uid);
    res.json({
        success: true,
        message: "Discord Account Verified"
    });
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
                    let watchLink = 'https://www.infinitecampus.xyz/InfiniteAdminMovies.html';
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
app.post("/send", blockDiscordIfDisabled, memoryUpload.single("file"), async (req, res) => {
    const { message, channelId } = req.body;
    const file = req.file;
    let targetChannel = channelId || DEFAULT_CHANNEL_ID;
    const ALLOWED_CHANNELS = new Set([
        '1464689808717774970',
        '1389703415810101308',
        '1389334335114580229',
        '1309160050904006696',
        '1309164699417448550',
        '1007051892821594183',
        '1086362556203028540',
        '1334945403912720586',
        '1390991482650886215',
        '1391898825588740108',
        '1401659961880088668',
        '1334377158789042226'
    ]);
    if (!requireAdminForChannel(req, res, ALLOWED_CHANNELS, targetChannel)) return;
    try {
        if (file) {
            const formData = new FormData();
            formData.append("content", message || "");
            formData.append("files[0]", file.buffer, {
                filename: file.originalname,
                contentType: file.mimetype,
            });
            await discordRequest({
                method: "post",
                url: `https://discord.com/api/v10/channels/${targetChannel}/messages`,
                data: formData,
                headers: formData.getHeaders(),
            });
            const report = loadReportJSON();
            const day = new Date().getDate().toString();
            if (!report.report[day]) report.report[day] = {};
            if (!report.report[day]["sent"]) report.report[day]["sent"] = { count: 0 };
            report.report[day]["sent"].count += 2;
            saveReportJSON(report);
        } else {
            await discordRequest({
                method: "post",
                url: `https://discord.com/api/v10/channels/${targetChannel}/messages`,
                data: { content: message },
                headers: { "Content-Type": "application/json" },
            });
            const report = loadReportJSON();
            const day = new Date().getDate().toString();
            if (!report.report[day]) report.report[day] = {};
            if (!report.report[day]["sent"]) report.report[day]["sent"] = { count: 0 };
            report.report[day]["sent"].count++;
            saveReportJSON(report);
        }
        res.status(200).send("Message Sent");
    } catch (err) {
        console.error("Discord Error:", err.response?.data || err.message);
        res.status(500).send("Failed To Send Message");
    }
});
app.post("/upload",blockDiscordIfDisabled,memoryUpload.single("file"), async (req, res) => {
    const { channelId } = req.body;
    const file = req.file;
    let targetChannel = channelId || DEFAULT_CHANNEL_ID;
    const ALLOWED_CHANNELS = new Set([
        '1464689808717774970',
        '1389703415810101308',
        '1389334335114580229',
        '1309160050904006696',
        '1309164699417448550',
        '1007051892821594183',
        '1086362556203028540',
        '1334945403912720586',
        '1390991482650886215',
        '1391898825588740108',
        '1401659961880088668',
        '1334377158789042226'
    ]);
    if (!requireAdminForChannel(req, res, ALLOWED_CHANNELS, targetChannel)) return;
    if (!file) return res.status(400).send("No File Uploaded");
        const MAX_SIZE = 10 * 1024 * 1024;
        if (file.size > MAX_SIZE) {
            fs.unlink(file.path, () => {});
            return res.status(400).send("File exceeds 10MB limit");
        }
        try {
            const formData = new FormData();
            formData.append("files[0]", fs.createReadStream(file.path), {
                filename: file.originalname,
                contentType: file.mimetype,
            });
            await discordRequest({
                method: "post",
                url: `https://discord.com/api/v10/channels/${targetChannel}/messages`,
                data: formData,
                headers: formData.getHeaders(),
            });
            logEvent("file-uploads", {
                id: `file_${Date.now()}`,
                data: {
                    author: req.headers["x-user-id"] || "unknown"
                }
            });
            fs.unlink(file.path, (err) => {
                if (err) console.error("Failed to delete temp file:", err);
            });
            res.status(200).send("File Uploaded");
        } catch (err) {
            if (file?.path) {
                fs.unlink(file.path, () => {});
            }
            console.error("File Upload Error:", err.response?.data || err.message);
            res.status(500).send("Failed To Upload File");
        }
    }
);
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
        );
        const nextNumber = Math.max(...numbers) + 1;
        const newFileName = `${nextNumber}${ext}`;
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
        await admin.database().ref(`users/${uid}/profile`).update({
            pic: nextNumber - 1
        });
        res.json({
            success: true,
            file: newFileName,
            picIndex: nextNumber - 1
        });
        await cleanupAndReindexPfps();
    } catch (err) {
        console.error("PFP Upload Error:", err.response?.data || err.message);
        res.status(500).json({ error: "Upload Failed" });
    }
});
const ACCLOGS_PATH = path.join(__dirname, "acclogs.json");
if (!fs.existsSync(ACCLOGS_PATH)) {
    fs.writeFileSync(ACCLOGS_PATH, JSON.stringify({}), "utf8");
}
function formatTimes(date) {
    return date.toLocaleString("en-US", {
        hour12: true
    });
}
function getIP(req) {
    return req.headers["x-forwarded-for"]?.split(",")[0] || req.socket?.remoteAddress || "unknown";
}
function loadAccLogs() {
    return JSON.parse(fs.readFileSync(ACCLOGS_PATH, "utf8") || "{}");
}
function saveAccLogs(data) {
    fs.writeFileSync(ACCLOGS_PATH, JSON.stringify(data, null, 2));
}
function cleanupLogsIfNeeded() {
    const CLEAR_DAY = parseInt(process.env.CLEAR_LOG_DAY || "1");
    const today = new Date().getDate();
    if (today === CLEAR_DAY) {
        saveAccLogs({});
        console.log("acclogs.json cleared for monthly reset");
    }
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
setInterval(() => {
    cleanupLogsIfNeeded();
    markExpiredTokens();
}, 60 * 1000);
app.post("/admin/createCustomToken", verifyFirebaseToken, async (req, res) => {
    try {
        const requesterUid = req.user.uid;
        const { targetUid } = req.body;
        if (!targetUid) {
            return res.status(400).json({ error: "Missing targetUid" });
        }
        const roleSnap = await admin.database()
            .ref(`users/${requesterUid}/profile/isOwner`)
            .get();
        if (!roleSnap.exists() || roleSnap.val() !== true) {
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
const uploadChunk = multer({ storage: multer.memoryStorage() });
app.post("/uploadthis", verifyFirebaseToken, uploadChunk.single("file"), async (req, res) => {
    if (LOCKDOWN) return res.status(403).json({ error: "Uploads Locked Down" });
    try {
        const userId = req.user?.uid;
        let maxAllowedSize = MAX_SIZE_NON_PREMIUM;
        if (userId) {
            try {
                const [
                    pre1Snap, pre2Snap, pre3Snap,
                    devSnap, adminSnap, HAdminSnap,
                    coOwnerSnap, testerSnap, ownerSnap, partnerSnap
                ] = await Promise.all([
                    admin.database().ref(`users/${userId}/profile/premium1`).get(),
                    admin.database().ref(`users/${userId}/profile/premium2`).get(),
                    admin.database().ref(`users/${userId}/profile/premium3`).get(),
                    admin.database().ref(`users/${userId}/profile/isDev`).get(),
                    admin.database().ref(`users/${userId}/profile/isAdmin`).get(),
                    admin.database().ref(`users/${userId}/profile/isHAdmin`).get(),
                    admin.database().ref(`users/${userId}/profile/isCoOwner`).get(),
                    admin.database().ref(`users/${userId}/profile/isTester`).get(),
                    admin.database().ref(`users/${userId}/profile/isOwner`).get(),
                    admin.database().ref(`users/${userId}/profile/isPartner`).get()
                ]);
                const isPremium =
                    (pre1Snap.exists() && pre1Snap.val()) ||
                    (pre2Snap.exists() && pre2Snap.val()) ||
                    (pre3Snap.exists() && pre3Snap.val()) ||
                    (devSnap.exists() && devSnap.val()) ||
                    (adminSnap.exists() && adminSnap.val()) ||
                    (HAdminSnap.exists() && HAdminSnap.val()) ||
                    (coOwnerSnap.exists() && coOwnerSnap.val()) ||
                    (testerSnap.exists() && testerSnap.val()) ||
                    (ownerSnap.exists() && ownerSnap.val()) ||
                    (partnerSnap.exists() && partnerSnap.val());
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
            const safeName = sanitize(originalFilename);
            const finalFilename = `${Date.now()}-${safeName}`;
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
                    const [
                        pre1Snap, pre2Snap, pre3Snap,
                        devSnap, adminSnap, HAdminSnap,
                        coOwnerSnap, testerSnap, ownerSnap, partnerSnap
                    ] = await Promise.all([
                        admin.database().ref(`users/${userId}/profile/premium1`).get(),
                        admin.database().ref(`users/${userId}/profile/premium2`).get(),
                        admin.database().ref(`users/${userId}/profile/premium3`).get(),
                        admin.database().ref(`users/${userId}/profile/isDev`).get(),
                        admin.database().ref(`users/${userId}/profile/isAdmin`).get(),
                        admin.database().ref(`users/${userId}/profile/isHAdmin`).get(),
                        admin.database().ref(`users/${userId}/profile/isCoOwner`).get(),
                        admin.database().ref(`users/${userId}/profile/isTester`).get(),
                        admin.database().ref(`users/${userId}/profile/isOwner`).get(),
                        admin.database().ref(`users/${userId}/profile/isPartner`).get()
                    ]);
                    const isPremium =
                        (pre1Snap.exists() && pre1Snap.val()) ||
                        (pre2Snap.exists() && pre2Snap.val()) ||
                        (pre3Snap.exists() && pre3Snap.val()) ||
                        (devSnap.exists() && devSnap.val()) ||
                        (adminSnap.exists() && adminSnap.val()) ||
                        (HAdminSnap.exists() && HAdminSnap.val()) ||
                        (coOwnerSnap.exists() && coOwnerSnap.val()) ||
                        (testerSnap.exists() && testerSnap.val()) ||
                        (ownerSnap.exists() && ownerSnap.val()) ||
                        (partnerSnap.exists() && partnerSnap.val());
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
rl.on("line", (input) => {
    const trimmed = input.trim();
    if (liveMode) {
        const files = fs.readdirSync(UPLOADS_DIR).filter((f) => {
            try {
                return fs.statSync(path.join(UPLOADS_DIR, f)).isFile();
            } catch {
                return false;
            }
        });
        if (trimmed.toUpperCase().startsWith("DELETE")) {
            const parts = trimmed.split(" ").filter(Boolean);
            const num = parseInt(parts[1]) - 1;
            if (!isNaN(num) && files[num]) {
                fs.unlinkSync(path.join(UPLOADS_DIR, files[num]));
                console.log(`\nDeleted ${files[num]}`);
            } else {
                console.log("\nInvalid File Number For DELETE.");
            }
        } else if (trimmed.toUpperCase() === "MENU") {
            liveMode = false;
            if (liveInterval) clearInterval(liveInterval);
            console.log("\nReturning To Main Menu");
            mainMenu();
            return;
        } else if (!isNaN(parseInt(trimmed))) {
            const num = parseInt(trimmed) - 1;
            if (files[num]) {
                const file = files[num];
                const url = `https://www.infinitecampus.xyz/InfiniteUploaders.html?file=${file}`;
                console.log(`\nDownload Link: ${url}`);
                activeLinks.push({ url, ts: Date.now() });
            } else {
                console.log("\nInvalid File Number.");
            }
        } else if (trimmed.length === 0) {
        } else {
            console.log(`\nUnknown Command: ${trimmed}`);
        }
    } else {
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
    const usersSnap = await admin.database().ref("users").once("value");
    const usedIndexes = new Set();
    usersSnap.forEach(userSnap => {
        const pic = userSnap.child("profile/pic").val();
        if (typeof pic === "number") {
            usedIndexes.add(pic);
        }
    });
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
    const updates = {};
    usersSnap.forEach(userSnap => {
        const uid = userSnap.key;
        const oldPic = userSnap.child("profile/pic").val();
        if (typeof oldPic === "number" && oldToNew.hasOwnProperty(oldPic)) {
            updates[`users/${uid}/profile/pic`] = oldToNew[oldPic];
        }
    });
    if (Object.keys(updates).length > 0) {
        await admin.database().ref().update(updates);
    }
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
            return { id: null, cover: null, vote_average: null };
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
            await db.ref(`users/${uid}/profile`).update(updates);
        } else {
            await db.ref(`users/${uid}/profile`).update({
                isDonater: true
            });
        }
        const displayName = (await db.ref(`users/${uid}/profile/displayName`).get()).val();
        if (amount >= 1000) {
            await sendDiscordEmbedPre({
                title: "Premium T3 Purchased",
                color: 0xFF0000,
                fields: [
                    { name: "Name", value: displayName, inline: false },
                    { name: "Amount", value: `$${(amount / 100).toFixed(2)}`, inline: true },
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
                    { name: "Amount", value: `$${(amount / 100).toFixed(2)}`, inline: true },
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
                    { name: "Amount", value: `$${(amount / 100).toFixed(2)}`, inline: true },
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
                    { name: "Amount", value: `$${(amount / 100).toFixed(2)}`, inline: true }
                ],
                timestamp: new Date().toISOString()
            });
        }
    } catch (err) {
        console.error("Premium Grant Error:", err, uid);
    }
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
                renderPinnedAccept();
                setTimeout(() => {
                    pinnedAcceptLine = null;
                    renderPinnedAccept();
                }, 3000);
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
async function sendVerificationNotification(uid, displayName) {
    const usersSnap = await db.ref("users").once("value");
    const tokens = [];
    for (const user of Object.keys(usersSnap.val() || {})) {
        const profile = usersSnap.child(user).child("profile");
        if (
            profile.child("isOwner").val() === true ||
            profile.child("isTester").val() === true ||
            profile.child("isCoOwner").val() === true ||
            profile.child("isDev").val() === true
        ) {
            const tokenSnap = await db.ref(`pushTokens/${user}`).once("value");
            tokenSnap.forEach(token => {
                tokens.push(token.key);
            });
        }
    }
    if (tokens.length === 0) {
        console.log("No Admin Tokens Found.");
        return;
    }
    const message = {
        data: {
            type: "verifyUser",
            uid: uid,
            url: `/InfiniteAdminChats.html`
        },
        notification: {
            title: "A New User Has Signed Up!",
            body: `User ${displayName} Is Awaiting Verification`
        },
        tokens: tokens
    };
    const response = await admin.messaging().sendEachForMulticast(message);
    console.log("Verification Notification Sent.");
    console.log("Success:", response.successCount);
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
            let realSize = 0;
            try{
                const fullpath = path.join(APPLY_DIR, movieName);
                if (fs.existsSync(fullPath)) {
                    realSize = fs.statSync(fullPath).size;
                }
            } catch {}
            updateApply(movieName, {
                status: status.message || "Processing",
                percent: Math.round(status.percent ?? 0),
                eta: status.remainingSec ?? 0,
                size: realSize
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
            const result = await discordRequest({
                method: "patch",
                url: `https://discord.com/api/v10/channels/${logid}/messages/${messageId}`,
                data: { embeds: [updatedEmbed] },
                headers: { "Content-Type": "application/json" }
            });
        } catch (err) {
            console.error("Discord Error:", err.response?.data || err.message);
        }
    }, 5000);
    setInterval(() => {
        for (const [movie, interval] of acceptIntervals) {
            if (!acceptStatus.has(movie)) {
                clearInterval(interval);
                acceptIntervals.delete(movie);
            }
        }
    }, 60000);
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
async function watchForNewUsers() {
    const snap = await db.ref("users").once("value");
    snap.forEach(child => {
        seenUsers.add(child.key);
    });
    setInterval(async () => {
        const usersSnap = await db.ref("users").once("value");
        for (const child of Object.keys(usersSnap.val() || {})) {
            if (!seenUsers.has(child)) {
                seenUsers.add(child);
                const profile = usersSnap.child(child).child("profile").val();
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
function getNextOrder(moviesJson) {
    const orders = Object.values(moviesJson).map(m => m.order);
    if (orders.length === 0) return 1;
    return Math.max(...orders) + 1;
}
function listFilesLive() {
    liveMode = true;
    if (liveInterval) clearInterval(liveInterval);
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
    liveInterval = setInterval(renderList, 1000);
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
function saveReportJSON(data) {
    fs.writeFileSync(REPORT_JSON, JSON.stringify(data, null, 2));
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
function ensureArchiveDir() {
    if (!fs.existsSync(ARCHIVE_DIR)) {
        fs.mkdirSync(ARCHIVE_DIR, { recursive: true });
    }
}
function archiveReport() {
    const now = new Date();
    const monthNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    const month = monthNames[now.getMonth()];
    const year = now.getFullYear();
    const archiveName = `${month}${year}report.json`;
    ensureArchiveDir();
    if (fs.existsSync(REPORT_JSON)) {
        const archivePath = path.join(ARCHIVE_DIR, archiveName);
        fs.copyFileSync(REPORT_JSON, archivePath);
        console.log(`Report archived as ${archiveName}`);
    }
    saveReportJSON({ report: {} });
}
function mainMenu() {
    liveMode = false;
    if (liveInterval) {
        clearInterval(liveInterval);
        liveInterval = null;
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
function renderPinnedAccept() {
    if (!pinnedAcceptLine) return;
    const currentInput = rl.line || "";
    const prompt = rl.getPrompt() || "> ";
    readline.cursorTo(process.stdout, 0, 0);
    readline.clearLine(process.stdout, 0);
    process.stdout.write(pinnedAcceptLine);
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
function saveApplyJSON(data) {
    fs.writeFileSync(APPLY_JSON, JSON.stringify(data, null, 4));
}
function saveMoviesJSON(data) {
    fs.writeFileSync(MOVIES_JSON, JSON.stringify(data, null, 4));
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
function setupSocketHandlers(ioInstance, label) {
    ioInstance.on("connection", (socket) => {
        console.log(`${label} Admin Socket Connected:`, socket.id);
        socket.on("acceptApplicant", async (payload) => {
            const { filename, targetName } = payload;
            const safeFile = path.basename(filename);
            const srcPath = path.join(APPLY_DIR, safeFile);
            if (!fs.existsSync(srcPath)) {
                return socket.emit("jobError", { filename: safeFile, message: "Source File Not Found" });
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
                            await db.ref(`users/${uploaderUid}/profile`).update({
                                isUploader: true
                            });
                        } catch (err) {
                            console.error("Failed To Grant Uploader Role:", err);
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
                pinnedAcceptLine = `ACCEPT FAILED: ${safeFile}`;
                renderPinnedAccept();
                setTimeout(() => {
                    pinnedAcceptLine = null;
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
        });
    });
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
}, 60 * 1000);
setInterval(async () => {
    try {
        const now = Date.now();
        const snap = await db.ref("users").once("value");
        if (!snap.exists()) return;
        const updates = {};
        snap.forEach(userSnap => {
            const uid = userSnap.key;
            const profile = userSnap.child("profile").val();
            if (!profile) return;
            if ((profile.premium1 || profile.premium2 || profile.premium3) === true  && profile.preExpire && now >= profile.preExpire) {
                updates[`users/${uid}/profile/premium1`] = null;
                updates[`users/${uid}/profile/premium2`] = null;
                updates[`users/${uid}/profile/premium3`] = null;
                updates[`users/${uid}/profile/preExpire`] = null;
            }
        });
        if (Object.keys(updates).length > 0) {
            await db.ref().update(updates);
            console.log("Expired Premium Removed For Users:", Object.keys(updates).length / 2);
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
    const now = new Date();
    const day = now.getDate();
    const hour = now.getHours();
    const minute = now.getMinutes();
    if (day === 1 && hour === 0 && minute === 0) {
        archiveReport();
    }
}, 60 * 1000);
process.on("SIGINT", () => {
    console.clear();
    console.log("\nExiting");
    process.exit(0);
});
httpServer.listen(PORT, () => {
    console.log(`Infinite Campus Server Running At http://localhost:${PORT}`);
    httpServer.setTimeout(0);
    httpServer.keepAliveTimeout = 0;
    httpServer.headersTimeout = 0;
    mainMenu();
});
setupSocketHandlers(ioLive, "LIVE");
setupSocketHandlers(ioRealtime, "REALTIME");
scheduleDailyClear();
restoreApplicantMessages();
watchForNewUsers();