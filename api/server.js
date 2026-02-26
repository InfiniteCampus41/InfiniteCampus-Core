import cors from "cors";
import express from "express";
import fetch from "node-fetch";
const app = express();
app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, uploadedby, ngrok-skip-browser-warning, x-admin-password, fileId, chunkIndex, totalChunks, filename, x-user-id, X-File-Id, X-Chunk-Number, X-Total-Chunks, X-Filename, X-User-Id");
    if (req.method === "OPTIONS") return res.sendStatus(200);
    next();
});
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
import Stripe from "stripe";
import admin from "firebase-admin";
import util from "util";
import os from "os";
import sanitize from "sanitize-filename";
import { Server as IOServer } from "socket.io";
const exec = util.promisify(util.promisify ? util.promisify : (fn => fn));
import child_process from "child_process";
const execProm = util.promisify(child_process.exec);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(cors({ origin: "*", methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"], allowedHeaders: [ "Content-Type", "Authorization", "ngrok-skip-browser-warning", "x-admin-password", "fileId", "chunkIndex", "totalChunks", "filename", "x-user-id", "X-File-Id", "X-Chunk-Number", "X-Total-Chunks", "X-User-Id", "uploadedby"]}));
app.post("/stripe-webhook",
    express.raw({ type: "application/json" }),
    async (req, res) => {
    const sig = req.headers["stripe-signature"];
    let event;
    try {
        event = stripe.webhooks.constructEvent(
            req.body,
            sig,
            process.env.STRIPE_WEBHOOK_SECRET
        );
    } catch (err) {
        console.log("Webhook signature failed.");
        return res.sendStatus(400);
    }
    if (event.type === "checkout.session.completed") {
        const session = event.data.object;
        const uid = session.metadata.firebaseUID;
        const amount = session.amount_total;
        await grantPremium(uid, amount);
    }
    res.sendStatus(200);
});
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
const PORT = process.env.PORT || 4000;
const uploadProgress = new Map();
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const DEFAULT_CHANNEL_ID = process.env.CHANNEL_ID;
const UPLOADS_DIR = path.join(__dirname, "uploads");
const APPLY_DIR = path.join(__dirname, "apply");
const UPLOADS_TEMP_DIR = path.join(__dirname, "uploads_temp");
const MOVIES_DIR = path.join(__dirname, "movies");
const READY_DIR = path.join(__dirname, "ready");
const QUEUE_DIR = path.join(__dirname, "queue");
const PFP_COOLDOWN_MS = 3 * 60 * 1000;
const pfpUploadCooldown = new Map();
const DISCORD_QUEUE_DIR = path.join(__dirname, "discord_queue");
const logid = "1460410323369721868";
const stripe = new Stripe(process.env.STRIPE_SECRET);
const acceptStatus = new Map();
setInterval(() => {
    if (acceptStatus.size > 500) {
        acceptStatus.clear();

    }
}, 10 * 60 * 1000);
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
if (!fs.existsSync(APPLY_DIR)) fs.mkdirSync(APPLY_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_TEMP_DIR)) fs.mkdirSync(UPLOADS_TEMP_DIR, { recursive: true });
if (!fs.existsSync(MOVIES_DIR)) fs.mkdirSync(MOVIES_DIR, { recursive: true });
if (!fs.existsSync(READY_DIR)) fs.mkdirSync(READY_DIR, { recursive: true });
if (!fs.existsSync(QUEUE_DIR)) fs.mkdirSync(QUEUE_DIR, { recursive: true });
if (!fs.existsSync(DISCORD_QUEUE_DIR)) fs.mkdirSync(DISCORD_QUEUE_DIR, { recursive: true });
const tempUploadActivity = new Map();
setInterval(() => {
    const now = Date.now();
    for (const [key,time] of tempUploadActivity) {
        if (now - time > TEMP_UPLOAD_TIMEOUT) {
            tempUploadActivity.delete(key);
        }
    }
}, 60 * 1000);
const TEMP_UPLOAD_TIMEOUT = 3 * 60 * 60 * 1000;
const MAX_SIZE_NON_PREMIUM = 100 * 1024 * 1024;
const MAX_SIZE_PREMIUM = 500 * 1024 * 1024;
let DISCORD_DISABLED = false;
const UNIQUE_SUFFIX = "x9a7b2";
const MOVIES_JSON = path.join(__dirname, "movies.json");
const ALLOWED_PFP_EXTS = new Set([".png", ".jpeg", ".jpg", ".webp", ".ico"]);
const pfpStorage = multer.memoryStorage();
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
let testEnabled = false;
if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert(JSON.parse(fs.readFileSync("./admin.json"))),
        databaseURL: "https://notes-27f22-default-rtdb.firebaseio.com"
    });
}
const db = admin.database();
const donationSessions = new Map();
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
function loadMoviesJSON() {
    if (!fs.existsSync(MOVIES_JSON)) return {};
    try {
        return JSON.parse(fs.readFileSync(MOVIES_JSON, "utf8"));
    } catch {
        return {};
    }
}
function saveMoviesJSON(data) {
    fs.writeFileSync(MOVIES_JSON, JSON.stringify(data, null, 4));
}
function getNextOrder(moviesJson) {
    const orders = Object.values(moviesJson).map(m => m.order);
    if (orders.length === 0) return 1;
    return Math.max(...orders) + 1;
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
app.post("/upload-pfp", uploadPfp.single("file"), async (req, res) => {
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
function requireAdminPassword(req, res, next) {
    const adminRoutes = [
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
app.use(requireAdminPassword);
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
app.post("/checkout", async (req, res) => {
    const { uid, amount } = req.body;
    const cents = Math.round(amount * 100);
    const session = await stripe.checkout.sessions.create({
        mode: "payment",
        payment_method_types: ["card"],
        line_items: [{
            price_data: {
                currency: "usd",
                product_data: { name: "Infinite Campus Premium" },
                unit_amount: cents
            },
            quantity: 1
        }],
        metadata: {
            firebaseUID: uid
        },
        success_url: `https://www.infinitecampus.xyz/InfiniteDonaters.html?success.${amount}`,
        cancel_url: "https://www.infinitecampus.xyz/InfiniteDonaters.html?cancel"
    });
    res.json({ id: session.id });
});
async function grantPremium(uid, amount) {
    try {
        if (amount >= 500) {
            const expireDate = new Date();
            expireDate.setMonth(expireDate.getMonth() + 3);
            const updates = {
                preExpire: expireDate.getTime()
            };
            if (amount >= 1500) updates.premium3 = true;
            else if (amount >= 1000) updates.premium2 = true;
            else if (amount >= 500) updates.premium1 = true;
            await db.ref(`users/${uid}/profile`).update(updates);
        } else {
            await db.ref(`users/${uid}/profile`).update({
                isDonater: true
            });
        }
        const displayName = (await db.ref(`users/${uid}/profile/displayName`).get()).val();
        if (amount >= 1500) {
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
        } else if (amount >= 1000) {
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
        } else if (amount >= 500) {
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
const MAX_DISCORD_QUEUE = 5000;
const DISCORD_QUEUE_TTL = 5 * 60 * 1000;
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
const UPLOAD_LIMIT_MB = 100;
const FOLDER_LIMIT_MB = 1024;
const AUTO_DELETE_MS = 5 * 60 * 1000;
const AUTO_DELETE_PM_MS = 15 * 60 * 1000;
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
const memoryUpload = multer({
    storage: multer.diskStorage({
        destination: UPLOADS_TEMP_DIR,
        filename: (req,file,cb)=>cb(null,Date.now()+"-"+file.originalname)
    })
});
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
setInterval(() => {
    pruneOldLogs();
}, 10 * 1000);
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
app.post("/upload", blockDiscordIfDisabled, memoryUpload.single("file"), async (req, res) => {
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
function formatSize(bytes) {
    if (!bytes) return "0 MB";
    const mb = bytes / (1024 * 1024);
    if (mb < 1024) {
        return mb.toFixed(2) + " MB";
    }
    const gb = mb / 1024;
    return gb.toFixed(2) + " GB";
}
const applicantMessages = new Map();
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
    return msg.data.id;
}
const acceptIntervals = new Map();
async function startAcceptProcess(movieName) {
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
    await discordRequest({
        method: "patch",
        url: `https://discord.com/api/v10/channels/${logid}/messages/${msgId}`,
        data: { embeds: [embed], components: [] },
        headers: { "Content-Type": "application/json" }
    });
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
    try {
        await discordRequest({
            method: "patch",
            url: `https://discord.com/api/v10/channels/${logid}/messages/${msgId}`,
            data: { embeds: [embed], components: [] },
            headers: { "Content-Type": "application/json" }
        });
    } catch (e) {
    }
}
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
app.post("/uploadthis", async (req, res) => {
    if (LOCKDOWN) return res.status(403).json({ error: "Uploads Locked Down" });
    const userId = req.headers["x-user-id"];
    let maxAllowedSize = MAX_SIZE_NON_PREMIUM;
    if (userId) {
        try {
            const pre1Snap = await admin.database().ref(`users/${userId}/profile/premium1`).get();
            const pre2Snap = await admin.database().ref(`users/${userId}/profile/premium2`).get();
            const pre3Snap = await admin.database().ref(`users/${userId}/profile/premium3`).get();
            const devSnap = await admin.database().ref(`users/${userId}/profile/isDev`).get();
            const adminSnap = await admin.database().ref(`users/${userId}/profile/isAdmin`).get();
            const HAdminSnap = await admin.database().ref(`users/${userId}/profile/isHAdmin`).get();
            const coOwnerSnap = await admin.database().ref(`users/${userId}/profile/isCoOwner`).get();
            const testerSnap = await admin.database().ref(`users/${userId}/profile/isTester`).get();
            const ownerSnap = await admin.database().ref(`users/${userId}/profile/isOwner`).get();
            const partnerSnap = await admin.database().ref(`users/${userId}/profile/isPartner`).get();
            const isPartner = partnerSnap.exists() && partnerSnap.val() === true;
            const isPre1 = pre1Snap.exists() && pre1Snap.val() === true;
            const isPre2 = pre2Snap.exists() && pre2Snap.val() === true;
            const isPre3 = pre3Snap.exists() && pre3Snap.val() === true;
            const isDev = devSnap.exists() && devSnap.val() === true;
            const isAdmin = adminSnap.exists() && adminSnap.val() === true;
            const isHAdmin = HAdminSnap.exists() && HAdminSnap.val() === true;
            const isCoOwner = coOwnerSnap.exists() && coOwnerSnap.val() === true;
            const isTester = testerSnap.exists() && testerSnap.val() === true;
            const isOwner = ownerSnap.exists() && ownerSnap.val() === true;
            if (isPre1 || isPre2 || isPre3 || isDev || isAdmin || isHAdmin || isCoOwner || isTester || isOwner || isPartner) {
                maxAllowedSize = MAX_SIZE_PREMIUM;
            }
        } catch (err) {
            console.error("Firebase Admin SDK Error:", err);
        }
    }
    const fileId = req.headers["x-file-id"];
    const chunkNumber = parseInt(req.headers["x-chunk-number"], 10);
    const totalChunks = parseInt(req.headers["x-total-chunks"], 10);
    const originalFilename = req.headers["x-filename"];
    if (!fileId || isNaN(chunkNumber) || isNaN(totalChunks) || !originalFilename) {
        return res.status(400).json({ error: "Missing Required Headers For Chunked Upload" });
    }
    const tmpDir = path.join(UPLOADS_DIR, "tmp", fileId);
    await fs.promises.mkdir(tmpDir, { recursive: true });
    const chunkPath = path.join(tmpDir, `chunk-${chunkNumber}`);
    const writeStream = fs.createWriteStream(chunkPath);
    let uploadedBytes = 0;
    req.on("data", (chunk) => {
        uploadedBytes += chunk.length;
        writeStream.write(chunk);
    });
    req.on("end", async () => {
        writeStream.end();
        const chunkFiles = fs.readdirSync(tmpDir);
        if (chunkFiles.length === totalChunks) {
            const finalFilename = `${Date.now()}-${originalFilename}`;
            const finalPath = path.join(UPLOADS_DIR, finalFilename);
            const finalStream = fs.createWriteStream(finalPath);
            for (let i = 1; i <= totalChunks; i++) {
                const chunkFile = path.join(tmpDir, `chunk-${i}`);
                const data = fs.readFileSync(chunkFile);
                finalStream.write(data);
                fs.unlinkSync(chunkFile);
            }
            finalStream.end();
            fs.rmdirSync(tmpDir);
            let deleteDelay = AUTO_DELETE_MS;
            try {
                const userId = req.headers["x-user-id"];
                if (userId) {
                    const pre1Snap = await admin.database().ref(`users/${userId}/profile/premium1`).get();
                    const pre2Snap = await admin.database().ref(`users/${userId}/profile/premium2`).get();
                    const pre3Snap = await admin.database().ref(`users/${userId}/profile/premium3`).get();
                    const devSnap = await admin.database().ref(`users/${userId}/profile/isDev`).get();
                    const adminSnap = await admin.database().ref(`users/${userId}/profile/isAdmin`).get();
                    const HAdminSnap = await admin.database().ref(`users/${userId}/profile/isHAdmin`).get();
                    const coOwnerSnap = await admin.database().ref(`users/${userId}/profile/isCoOwner`).get();
                    const testerSnap = await admin.database().ref(`users/${userId}/profile/isTester`).get();
                    const ownerSnap = await admin.database().ref(`users/${userId}/profile/isOwner`).get();
                    const partnerSnap = await admin.database().ref(`users/${userId}/profile/isPartner`).get();
                    const isPartner = partnerSnap.exists() && partnerSnap.val() === true;
                    const isPre1 = pre1Snap.exists() && pre1Snap.val() === true;
                    const isPre2 = pre2Snap.exists() && pre2Snap.val() === true;
                    const isPre3 = pre3Snap.exists() && pre3Snap.val() === true;
                    const isDev = devSnap.exists() && devSnap.val() === true;
                    const isAdmin = adminSnap.exists() && adminSnap.val() === true;
                    const isHAdmin = HAdminSnap.exists() && HAdminSnap.val() === true;
                    const isCoOwner = coOwnerSnap.exists() && coOwnerSnap.val() === true;
                    const isTester = testerSnap.exists() && testerSnap.val() === true;
                    const isOwner = ownerSnap.exists() && ownerSnap.val() === true;
                    if (isPre1 || isPre2 || isPre3 || isDev || isAdmin || isHAdmin || isCoOwner || isTester || isOwner || isPartner) {
                        deleteDelay = AUTO_DELETE_PM_MS;
                    }
                }
            } catch (err) {
                console.error("Premium check failed:", err);
            }
            setTimeout(() => fs.unlink(finalPath, () => {}), deleteDelay);
            pushUploadLog(finalFilename, uploadedBytes);
            return res.json({
                fileUrl: `${req.protocol}://${req.get("host")}/files/${finalFilename}`,
                message: "File Uploaded And Combined Successfully"
            });
        } else {
            return res.json({
                message: `Chunk ${chunkNumber} Uploaded Successfully`
            });
        }
    });
    req.on("error", (err) => {
        console.error(err);
        writeStream.end();
        res.status(500).json({ error: "Chunk Upload Failed" });
    });
});
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
app.post("/admin/lockdown", (req, res) => {
    const pass = req.headers["x-admin-password"];
    if (pass === process.env.NITRIX67 || process.env.DON_PASS_1) {
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
const MAX_FILE_BYTES = 1024 * 1024 * 1024 * 30;
const MAX_APPLY_BYTES = 30 * 1024 * 1024 * 1024;
const ALLOWED_EXTS = new Set([".mp4", ".mov", ".mkv", ".ts", ".webm", ".avi", ".flv", ".mpeg", ".mpg", ".m4v",]);
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
app.post(ROUTES.UPLOAD, express.raw({ limit: "5mb", type: "*/*" }), (req, res) => {
    const uploadedBy = req.headers.uploadedby || "User";
    const uid = req.headers["x-user-id"] || "unknown";
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
setInterval(() => {
    const now = Date.now();
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
            uploadedBy: moviesJson[f]?.uploadedBy || "User"
        };
    });
    list.sort((a, b) => a.order - b.order);
    return list;
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
	    finishReject(filename);
	    applicantMessages.delete(filename);
	    acceptStatus.delete(filename);
	    return res.json({ ok: true });
    } catch (err) {
        return res.json({ ok: false, message: err.message });
    }
});
app.post("/admin/discord_toggle", async (req, res) => {
    const pass = req.headers["x-admin-password"];
    if (pass === process.env.NITRIX67 || process.env.DON_PASS_1) {
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
                await runFfmpegWithProgress(socket, workId, safeFile, safeFile, srcPath, copyPath, duration, ["-y", "-i", srcPath, "-c", "copy", copyPath], "Copying Container" );
                try { fs.unlinkSync(srcPath); socket.emit("jobLog", { filename: safeFile, text: "Deleted Original" }); } catch (e) { socket.emit("jobLog", { filename: safeFile, text: "Could Not Delete Original (Non-Fatal)." }); }
                await new Promise(r => setTimeout(r, 500));
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
                let uploader = "User";
                try {
                    const metaPath = path.join(APPLY_DIR, safeFile + ".json");
                    let uploaderUid = null;
                    if (fs.existsSync(metaPath)) {
                        const meta = JSON.parse(fs.readFileSync(metaPath));
                        uploader = meta.uploadedBy || "User";
                        uploaderUid = meta.uid || null;
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
		        if (!moviesJson[baseName]) {
    		        moviesJson[baseName] = {
                        order: getNextOrder(moviesJson),
                        uploadedBy: uploader
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
setupSocketHandlers(ioLive, "LIVE");
setupSocketHandlers(ioRealtime, "REALTIME");
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
                console.clear();
                process.exit(0);
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