import cors from "cors";
import express from "express";
import fetch from "node-fetch";
const app = express();
app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, ngrok-skip-browser-warning, fileId, chunkIndex, totalChunks, filename");
    if (req.method === "OPTIONS") return res.sendStatus(200);
    next();
});
app.use(cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: [
        "Content-Type",
        "Authorization",
        "ngrok-skip-browser-warning",
        "fileId",
        "chunkIndex",
        "totalChunks",
        "filename"
    ]
}));
import dotenv from "dotenv";
dotenv.config();
import axios from "axios";
import path from "path";
import multer from "multer";
import fs from "fs";
import readline from "readline";
import FormData from "form-data";
import { fileURLToPath } from "url";
import { createServer } from "http";
import { spawn } from "child_process";
import util from "util";
import os from "os";
import sanitize from "sanitize-filename";
import { Server as IOServer } from "socket.io";
const exec = util.promisify(util.promisify ? util.promisify : (fn => fn));
import child_process from "child_process";
const execProm = util.promisify(child_process.exec);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(cors({
    origin: '*',
    methods: ['GET','POST','PUT','DELETE','OPTIONS'],
    allowedHeaders: ['Content-Type','Authorization','ngrok-skip-browser-warning'],
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
const PORT = process.env.PORT || 4000;
const uploadProgress = new Map();
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const DEFAULT_CHANNEL_ID = process.env.CHANNEL_ID;
const DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1385636456722206780/nhu-8Qv6CU_GzPWSPbRtnM2WVn3ra9psL0_K2e_5MJl-k8ES75CGgvuFeYRO-19aftsO";
app.use(express.static(path.join(__dirname, "public")));
const UPLOADS_DIR = path.join(__dirname, "uploads");
const APPLY_DIR = path.join(__dirname, "apply");
const UPLOADS_TEMP_DIR = path.join(__dirname, "uploads_temp");
const MOVIES_DIR = path.join(__dirname, "movies");
const READY_DIR = path.join(__dirname, "ready");
const QUEUE_DIR = path.join(__dirname, "queue");
const DISCORD_QUEUE_DIR = path.join(__dirname, "discord_queue");
const acceptStatus = new Map();
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
if (!fs.existsSync(APPLY_DIR)) fs.mkdirSync(APPLY_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_TEMP_DIR)) fs.mkdirSync(UPLOADS_TEMP_DIR, { recursive: true });
if (!fs.existsSync(MOVIES_DIR)) fs.mkdirSync(MOVIES_DIR, { recursive: true });
if (!fs.existsSync(READY_DIR)) fs.mkdirSync(READY_DIR, { recursive: true });
if (!fs.existsSync(QUEUE_DIR)) fs.mkdirSync(QUEUE_DIR, { recursive: true });
if (!fs.existsSync(DISCORD_QUEUE_DIR)) fs.mkdirSync(DISCORD_QUEUE_DIR, { recursive: true });
async function sendDiscordEmbed(embed) {
    await fetch(DISCORD_WEBHOOK_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ embeds: [embed] })
    });
}
app.post("/github-webhook", async (req, res) => {
    const event = req.headers["x-github-event"];
    const payload = req.body;
    try {
        let embed = {
            color: 0x92C83E,
            timestamp: new Date().toISOString()
        };
        if (event === "push") {
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
function formatBytes(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
    return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}
function safeName(original) {
    const ext = path.extname(original).toLowerCase();
    const base = sanitize(path.parse(original).name).replace(/\s+/g, "_") || "file";
    const ts = Date.now();
    return `${base}_${ts}${ext || ".mp4"}`;
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
const DISCORD_RPS = 48;
const discordQueue = [];
let discordQueueProcessing = false;
function enqueueDiscordRequest(axiosConfig) {
    return new Promise((resolve, reject) => {
        discordQueue.push({ axiosConfig, resolve, reject, createdAt: Date.now() });
    });
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
async function discordRequest({ method = "get", url, headers = {}, data = null, params = null }) {
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
const UPLOAD_LIMIT_MB = 100;
const FOLDER_LIMIT_MB = 1024;
const AUTO_DELETE_MS = 5 * 60 * 1000;
let LOCKDOWN = false;
function getFolderSize(folderPath) {
    const files = fs.readdirSync(folderPath);
    let total = 0;
    for (const f of files) {
        const stats = fs.statSync(path.join(folderPath, f));
        if (stats.isFile()) total += stats.size;
    }
    return total;
}
const diskStorage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOADS_DIR),
    filename: (req, file, cb) => {
        const uniqueName = Date.now() + "-" + file.originalname.replace(/\s+/g, "_");
        cb(null, uniqueName);
    },
});
const diskUpload = multer({ storage: diskStorage, limits: { fileSize: UPLOAD_LIMIT_MB * 1024 * 1024 } });
const memoryUpload = multer();
const uploadLogs = [];
const rateLimitLogs = [];
let activeLinks = [];
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
    uploadLogs.push({ message: msg, ts: now });
    console.log(msg);
}
setInterval(() => {
    pruneOldLogs();
}, 10 * 1000);
setInterval(() => {
    pruneOldLogs();
}, 10 * 1000);
app.post("/send", memoryUpload.single("file"), async (req, res) => {
    const { message, channelId } = req.body;
    const file = req.file;
    const targetChannel = channelId || DEFAULT_CHANNEL_ID;
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
        } else {
            await discordRequest({
                method: "post",
                url: `https://discord.com/api/v10/channels/${targetChannel}/messages`,
                data: { content: message },
                headers: { "Content-Type": "application/json" },
            });
        }
        res.status(200).send("Message Sent");
    } catch (err) {
        console.error("Discord Error:", err.response?.data || err.message);
        res.status(500).send("Failed To Send Message");
    }
});
app.post("/upload", memoryUpload.single("file"), async (req, res) => {
    const { channelId } = req.body;
    const file = req.file;
    const targetChannel = channelId || DEFAULT_CHANNEL_ID;
    if (!file) return res.status(400).send("No File Uploaded");
    try {
        const formData = new FormData();
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
        res.status(200).send("File Uploaded");
    } catch (err) {
        console.error("File Upload Error:", err.response?.data || err.message);
        res.status(500).send("Failed To Upload File");
    }
});
app.get("/api/messages", async (req, res) => {
    const channelId = req.query.channelId || DEFAULT_CHANNEL_ID;
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
app.post("/react", async (req, res) => {
    const { messageId, emoji, channelId } = req.body;
    if (!messageId || !emoji) return res.status(400).send("Missing MessageId Or Emoji");
    const targetChannel = channelId || DEFAULT_CHANNEL_ID;
    const emojiEncoded = encodeURIComponent(emoji);
    try {
        await discordRequest({
            method: "put",
            url: `https://discord.com/api/v10/channels/${targetChannel}/messages/${messageId}/reactions/${emojiEncoded}/@me`,
            data: {},
        });
        res.status(200).send("Reaction Added");
    } catch (err) {
        console.error("React Error:", err.response?.data || err.message);
        res.status(500).send("Failed To Add Reaction");
    }
});
app.post("/edit", async (req, res) => {
    const { messageId, newContent, channelId } = req.body;
    if (!messageId || !newContent) return res.status(400).send("Missing MessageId Or NewContent");
    const targetChannel = channelId || DEFAULT_CHANNEL_ID;
    try {
        await discordRequest({
            method: "patch",
            url: `https://discord.com/api/v10/channels/${targetChannel}/messages/${messageId}`,
            data: { content: newContent },
            headers: { "Content-Type": "application/json" },
        });
        res.status(200).send("Message Edited");
    } catch (err) {
        console.error("Edit Error:", err.response?.data || err.message);
        res.status(500).send("Failed To Edit Message");
    }
});
app.post("/uploadthis", 
    (req, res, next) => {
        if (LOCKDOWN) return res.status(403).json({ error: "Uploads Locked Down" });
        const totalSize = getFolderSize(UPLOADS_DIR);
        if (totalSize >= FOLDER_LIMIT_MB * 1024 * 1024) {
            return res.status(400).json({ error: "Storage Capacity Met (1GB)" });
        }
        const contentLength = Number(req.headers["content-length"] || 0);
        const startTime = Date.now();
        const id = req.ip;
        uploadProgress.set(id, {
            total: contentLength,
            uploaded: 0,
            startTime
        });
        req.on("data", (chunk) => {
            const info = uploadProgress.get(id);
            if (!info) return;
            info.uploaded += chunk.length;
            const elapsed = (Date.now() - info.startTime) / 1000;
            const speed = info.uploaded / elapsed;
            const remainingBytes = info.total - info.uploaded;
            const remainingSec = speed > 0 ? remainingBytes / speed : 0;
            info.percent = Math.min(
                100,
                Math.round((info.uploaded / info.total) * 100)
            );
            info.remainingSec = Math.round(remainingSec);
        });
        res.on("finish", () => {
            uploadProgress.delete(id);
        });
        next();
    },
    diskUpload.single("file"), (req, res) => {
        if (!req.file) return res.status(400).json({ error: "No File Uploaded" });
        const filePath = path.join(UPLOADS_DIR, req.file.filename);
        setTimeout(() => {
            fs.unlink(filePath, () => {});
        }, AUTO_DELETE_MS);
        pushUploadLog(req.file.filename, req.file.size);
        res.json({
            fileUrl: `${req.protocol}://${req.get("host")}/files/${req.file.filename}`
        });
    }
);
app.use("/files", (req, res, next) => {
    const downloadQuery = req.query.download;
    if (downloadQuery) {
        const filePath = path.join(UPLOADS_DIR, req.path);
        if (fs.existsSync(filePath)) return res.download(filePath);
        else return res.status(404).send("File Not Found");
    }
    next();
});
app.get("/files/:filename", (req, res) => {
    const fileName = req.params.filename;
    const filePath = path.join(UPLOADS_DIR, fileName);
    if (!fs.existsSync(filePath)) return res.status(404).send("File Not Found");
    res.setHeader("Content-Disposition", `attachment; filename="${fileName}"`);
    res.setHeader("Content-Type", "application/octet-stream");
    fs.createReadStream(filePath).pipe(res);
});
app.get("/admin/files", (req, res) => {
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
app.delete("/admin/files/:filename", (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(UPLOADS_DIR, filename);
    if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        return res.json({ success: true });
    }
    res.status(404).json({ error: "File Not Found" });
});
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "test.html"));
});
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
scheduleDailyClear();
app.get("/admin/logs", (req, res) => {
    res.json({
        uploadLogs: uploadLogs.slice(-100),
        rateLimitLogs: rateLimitLogs.slice(-100),
        activeLinks: activeLinks.slice(-100),
    });
});
app.post("/admin/lockdown", (req, res) => {
    LOCKDOWN = !LOCKDOWN;
    console.log(`LOCKDOWN Is Now ${LOCKDOWN ? "ON" : "OFF"} Via Remote Toggle`);
    res.json({ lockdown: LOCKDOWN });
});
const MAX_FILE_BYTES = 1024 * 1024 * 1024 * 30;
const MAX_APPLY_BYTES = 30 * 1024 * 1024 * 1024;
const ALLOWED_EXTS = new Set([
    ".mp4",
    ".mov",
    ".mkv",
    ".ts",
    ".webm",
    ".avi",
    ".flv",
    ".mpeg",
    ".mpg",
    ".m4v",
]);
const storageApply = multer.diskStorage({
    destination: (req, file, cb) => cb(null, APPLY_DIR),
    filename: (req, file, cb) => cb(null, safeName(file.originalname)),
});
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
const UNIQUE_SUFFIX = "x9a7b2";
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
app.post(ROUTES.UPLOAD, express.raw({ limit: "2mb", type: "*/*" }), (req, res) => {
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
                    res.json({
                        ok: true,
                        filename: safeFile,
                        size: fs.statSync(finalPath).size
                    });
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
app.get(ROUTES.LIST_APPLY, (req, res) => {
    try {
        const files = fs.readdirSync(APPLY_DIR);
        const list = files
        .map((f) => {
            const p = path.join(APPLY_DIR, f);
            const s = fs.statSync(p);
            return {
                file: f,
                size: s.size,
                mtime: s.mtime,
                humanSize: formatBytes(s.size),
            };
        })
        .sort((a, b) => b.mtime - a.mtime);
        res.json({ ok: true, list, folderSize: folderSizeBytes(APPLY_DIR) });
    } catch (e) {
        console.error(e);
        res.status(500).json({ ok: false, message: "Failed To List Applicants" });
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
function listMovies() {
    const files = fs.readdirSync(MOVIES_DIR).filter((f) => {
        const ext = path.extname(f).toLowerCase();
        return ext === ".mp4";
    });
    return files.map((f) => {
        const s = fs.statSync(path.join(MOVIES_DIR, f));
        return { file: f, name: path.parse(f).name, size: s.size, mtime: s.mtime, humanSize: formatBytes(s.size) };
    }).sort((a, b) => b.mtime - a.mtime);
}
app.get(ROUTES.LIST_VIDEOS, (req, res) => {
    try {
        res.json({ ok: true, videos: listMovies() });
    } catch (e) {
        res.status(500).json({ ok: false });
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
app.get("/accept_status/:file", (req, res) => {
    const file = path.basename(req.params.file);
    const status = acceptStatus.get(file);
    if (!status) {
        return res.json({
            exists: false,
            status: "idle"
        });
    }
    res.json({
        exists: true,
        file,
        ...status
    });
});
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
}, 30_000);
app.get(ROUTES.DOWNLOAD_VIDEO, (req, res) => {
    const name = path.basename(req.params.name);
    const file = path.join(MOVIES_DIR, name + ".mp4");
    if (!file.startsWith(MOVIES_DIR) || !fs.existsSync(file)) return res.status(404).send("Not Found");
    res.download(file, `${name}.mp4`);
});
app.delete(ROUTES.DELETE_VIDEO, (req, res) => {
    const name = path.basename(req.params.name);
    const file = path.join(MOVIES_DIR, name + ".mp4");
    if (!fs.existsSync(file)) return res.status(404).send("Not Found");
    fs.unlinkSync(file);
    res.json({ ok: true });
});
app.post(`/api/delete_apply_${UNIQUE_SUFFIX}`, express.json(), (req, res) => {
    const { filename } = req.body;
    if (!filename) return res.json({ ok: false, message: "No Filename Provided" });
    const full = path.join(APPLY_DIR, filename);
    if (!fs.existsSync(full)) return res.json({ ok: false, message: "Not Found" });
    try {
        fs.unlinkSync(full);
        return res.json({ ok: true });
    } catch (err) {
        return res.json({ ok: false, message: err.message });
    }
});
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
                await runFfmpegWithProgress(
    socket,
    workId,
    safeFile,
    safeFile,
    srcPath,
    copyPath,
    duration,
    ["-y", "-i", srcPath, "-c", "copy", copyPath],
    "Copying Container"
);
                try { fs.unlinkSync(srcPath); socket.emit("jobLog", { filename: safeFile, text: "Deleted Original" }); } catch (e) { socket.emit("jobLog", { filename: safeFile, text: "Could Not Delete Original (Non-Fatal)." }); }
                await runFfmpegWithProgress(
    socket,
    workId,
    safeFile,
    copyName,
    copyPath,
    scaledPathTemp,
    duration,
    ["-y", "-i", copyPath, "-vf", "scale=640:360", "-c:a", "copy", scaledPathTemp],
    "Scaling to 640x360"
);
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
                acceptStatus.set(safeFile, {
                    status: "completed",
                    percent: 100,
                    remainingSec: 0,
                    message: "Completed",
                    updated: Date.now()
                });
                socket.emit("jobDone", { filename: safeFile, finalName: path.basename(finalDest) });
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
setupSocketHandlers(ioLive, "LIVE");
setupSocketHandlers(ioRealtime, "REALTIME");
async function runFfmpegWithProgress(
    socket,
    workId,
    statusKey,
    filenameLabel,
    inputPath,
    outputPath,
    knownDuration,
    ffmpegArgs,
    humanLabel
) {
    return new Promise((resolve, reject) => {
        socket.emit("jobLog", { filename: filenameLabel, text: `${humanLabel} — starting` });
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
                    const pct = Math.round(percent);
                    const etaText = formatETA(remainingSec);
                    pinnedAcceptLine =
                        `ACCEPTING: ${filenameLabel} | ${humanLabel} | ${pct}% | ETA ${etaText}`;
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
                pinnedAcceptLine = `ACCEPT COMPLETE: ${filenameLabel}`;
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
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
rl.setPrompt("> ");
let liveInterval = null;
let liveMode = false;
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
                process.exit(0);
                break;
            default:
                console.log("Invalid Choice");
                mainMenu();
        }
    });
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
let pinnedAcceptLine = null;
function renderPinnedAccept() {
    if (!pinnedAcceptLine) return;
    const currentInput = rl.line || "";
    const prompt = rl.getPrompt() || "> ";
    readline.cursorTo(process.stdout, 0, 0);
    readline.clearLine(process.stdout, 0);
    process.stdout.write(pinnedAcceptLine);
    readline.cursorTo(process.stdout, prompt.length + currentInput.length);
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
function toggleLockdown() {
    LOCKDOWN = !LOCKDOWN;
    console.log(LOCKDOWN ? "Uploads Locked." : "Uploads Unlocked.");
    mainMenu();
}
process.on("SIGINT", () => {
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