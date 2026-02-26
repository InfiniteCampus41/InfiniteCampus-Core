import crypto from "crypto";
import { exec } from "child_process";
import { createServer } from "node:http";
import { fileURLToPath } from "url";
import { hostname } from "node:os";
import { server as wisp, logging } from "@mercuryworkshop/wisp-js/server";
import Fastify from "fastify";
import fastifyStatic from "@fastify/static";
import { scramjetPath } from "@mercuryworkshop/scramjet/path";
import { libcurlPath } from "@mercuryworkshop/libcurl-transport";
import { baremuxPath } from "@mercuryworkshop/bare-mux/node";
import fs from "fs/promises";
import path from "path";
import dotenv from "dotenv";
dotenv.config();
const publicPath = fileURLToPath(new URL("../public/", import.meta.url));
logging.set_level(logging.NONE);
Object.assign(wisp.options, {
    allow_udp_streams: false,
});
const REPO_URL = process.env.REPO_URL;
const BRANCH = process.env.BRANCH;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;
const REPO_CLONE_PATH = "./repo-cache";
const PUBLIC_DIR = publicPath;
const LOG_FILE = "log.json";
const URLS_FILE = "urls.json";
const ADMIN_PASSWORDS = (process.env.ADMIN_PASSWORDS || "")
    .split(",")
    .map(p => p.trim())
    .filter(Boolean);
function requireAdmin(req, reply) {
    const password = req.headers["x-admin-password"];
    if (!password || !ADMIN_PASSWORDS.includes(password)) {
        reply.code(403).send({ error: "Access Denied" });
        return false;
    }
    return true;
}
let blockedUrls = {};
function run(cmd) {
    return new Promise((resolve, reject) => {
        exec(cmd, { maxBuffer: 1024 * 1024 * 10 }, (err, stdout, stderr) => {
            if (err) {
                if (err.code === 137) {
                    console.error(`Command killed (137): ${cmd}`);
                    process.exit(137);
                }
                return reject(stderr || stdout || err);
            }
            resolve(stdout);
        });
    });
}
async function syncRepoToPublic(src, dest) {
    const [srcEntries, destEntries] = await Promise.all([
        fs.readdir(src, { withFileTypes: true }),
        fs.readdir(dest, { withFileTypes: true }).catch(() => [])
    ]);
    const srcNames = new Set(srcEntries.map(e => e.name));
    for (const destEntry of destEntries) {
        if (destEntry.name === ".git") continue;
        if (!srcNames.has(destEntry.name)) {
            const destPath = path.join(dest, destEntry.name);
            await fs.rm(destPath, { recursive: true, force: true });
        }
    }
    for (const entry of srcEntries) {
        if (entry.name === ".git") continue;
        const srcPath = path.join(src, entry.name);
        const destPath = path.join(dest, entry.name);
        if (entry.isDirectory()) {
            await fs.mkdir(destPath, { recursive: true });
            await syncRepoToPublic(srcPath, destPath);
        } else {
            let copy = true;
            try {
                const [srcStat, destStat] = await Promise.all([
                    fs.stat(srcPath),
                    fs.stat(destPath)
                ]);
                if (srcStat.mtimeMs <= destStat.mtimeMs && srcStat.size === destStat.size) {
                    copy = false;
                }
            } catch {
                copy = true;
            }
            if (copy) {
                await fs.copyFile(srcPath, destPath);
                console.log(`Updated: ${destPath}`);
            }
        }
    }
}
async function cloneOrPullRepo() {
    try {
        await fs.access(REPO_CLONE_PATH);
        console.log("Fetching Repo");
        await run(`git -C ${REPO_CLONE_PATH} fetch origin ${BRANCH}`);
        await run(`git -C ${REPO_CLONE_PATH} reset --hard origin/${BRANCH}`);
    } catch {
        console.log("Cloning Repo");
        await run(`git clone --branch ${BRANCH} ${REPO_URL} ${REPO_CLONE_PATH}`);
    }
    console.log("Syncing Repo");
    await fs.mkdir(PUBLIC_DIR, { recursive: true });
    const repoPublicPath = path.join(REPO_CLONE_PATH, "public");
    try {
        await fs.access(repoPublicPath);
        await syncRepoToPublic(repoPublicPath, PUBLIC_DIR);
    } catch {
        await syncRepoToPublic(REPO_CLONE_PATH, PUBLIC_DIR);
    }
    console.log("Synced");
}
async function loadBlockedUrls() {
    try {
        const data = await fs.readFile(URLS_FILE, "utf-8");
        blockedUrls = JSON.parse(data);
    } catch {
        blockedUrls = {};
    }
}
function verifySignature(req) {
    const sig = req.headers["x-hub-signature-256"];
    if (!sig) return false;
    const hmac = crypto.createHmac("sha256", WEBHOOK_SECRET);
    const digest = "sha256=" + hmac.update(req.rawBody).digest("hex");
    try {
        return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(digest));
    } catch {
        return false;
    }
}
async function saveBlockedUrls() {
    await fs.writeFile(URLS_FILE, JSON.stringify(blockedUrls, null, 2));
}
async function logUrlVisit(url) {
    let logs = {};
    try {
        const data = await fs.readFile(LOG_FILE, "utf-8");
        logs = JSON.parse(data);
    } catch {}
    const now = new Date().toISOString();
    if (!logs[url]) logs[url] = { count: 1, lastVisit: now };
    else {
        logs[url].count += 1;
        logs[url].lastVisit = now;
    }
    await fs.writeFile(LOG_FILE, JSON.stringify(logs, null, 2));
}
async function clearLogs() {
    try {
        await fs.writeFile(LOG_FILE, "{}");
        console.log("Logs Cleared.");
    } catch (err) {
        console.error("Failed To Clear Logs:", err);
    }
}
function scheduleDailyLogClear() {
    const now = new Date();
    const next10PM = new Date();
    next10PM.setHours(22, 0, 0, 0);
    if (now > next10PM) next10PM.setDate(next10PM.getDate() + 1);
    const msUntil10PM = next10PM - now;
    setTimeout(() => {
        clearLogs();
        setInterval(clearLogs, 24 * 60 * 60 * 1000);
    }, msUntil10PM);
}
const fastify = Fastify({
    serverFactory: (handler) => {
        return createServer()
        .on("request", (req, res) => {
            res.setHeader("Access-Control-Allow-Origin", "*");
            res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
            res.setHeader("Access-Control-Allow-Headers", "*");
            if (req.method === "OPTIONS") {
                res.writeHead(204);
                res.end();
                return;
            }
            handler(req, res);
        })
        .on("upgrade", (req, socket, head) => {
            if (req.url.endsWith("/wisp/")) wisp.routeRequest(req, socket, head);
            else socket.end();
        });
    },
});
fastify.register(fastifyStatic, { root: publicPath, decorateReply: true });
fastify.register(fastifyStatic, { root: scramjetPath, prefix: "/scram/", decorateReply: false });
fastify.register(fastifyStatic, { root: libcurlPath, prefix: "/libcurl/", decorateReply: false });
fastify.register(fastifyStatic, { root: baremuxPath, prefix: "/baremux/", decorateReply: false });
fastify.addHook("onSend", async (req, reply, payload) => {
    if (req.url.startsWith("/scram/sw.js")) {
        reply.header("Service-Worker-Allowed", "/");
        reply.header("Cache-Control", "no-store");
    }
});
fastify.get("/", (req, reply) => {
    reply.sendFile("index.html");
});
fastify.addContentTypeParser("*", { parseAs: "buffer" }, (req, body, done) => {
    req.rawBody = body;
    done(null, body);
});
fastify.addContentTypeParser(
    "application/json",
    { parseAs: "buffer" },
    (req, body, done) => {
        req.rawBody = body;
        try {
            const json = JSON.parse(body.toString());
            done(null, json);
        } catch (err) {
            done(err, undefined);
        }
    }
);
fastify.post("/github-webhook", async (request, reply) => {
    if (!verifySignature(request)) {
        console.log("Webhook Invalid");
        return reply.code(401).send({ error: "Invalid Signature" });
    }
    const event = request.headers["x-github-event"];
    if (event !== "push") {
        console.log(`Ignored GitHub Event: ${event}`);
        return reply.code(200).send({ ignored: true });
    }
    console.log("Updating Repo");
    try {
        await cloneOrPullRepo();
        console.log("Updated");
        reply.send({ success: true });
    } catch (err) {
        console.error("Failed To Update:", err);
        reply.code(500).send({ error: err.toString() });
    }
});
fastify.get("/edit-urls", async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    await loadBlockedUrls();
    reply.send(blockedUrls);
});
fastify.post("/edit-urls/add", async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const { url, reason } = req.body;
    if (!url || !reason) return reply.code(400).send({ error: "Missing URL Or Reason" });
    await loadBlockedUrls();
    if (blockedUrls[url]) return reply.code(400).send({ error: "URL Already Exists" });
    blockedUrls[url] = reason;
    await saveBlockedUrls();
    reply.send({ success: true, message: "URL Added" });
});
fastify.post("/edit-urls/delete", async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const { url } = req.body;
    if (!url) return reply.code(400).send({ error: "Missing URL" });
    await loadBlockedUrls();
    if (!blockedUrls[url]) return reply.code(404).send({ error: "URL Not Found" });
    delete blockedUrls[url];
    await saveBlockedUrls();
    reply.send({ success: true, message: "URL Removed" });
});
fastify.route({
    method: ["GET", "POST"],
    url: "/logs",
    handler: async (req, reply) => {
        let logs = {};
        try {
            const data = await fs.readFile(LOG_FILE, "utf-8");
            logs = JSON.parse(data);
        } catch {}
        if (req.method === "GET") {
            if (!requireAdmin(req, reply)) return;
        }
        if (req.method === "GET") return reply.code(200).send(logs);
        if (req.method === "POST") {
            const { url } = req.body || {};
            if (!url) return reply.code(400).send({ error: "Missing URL In Body" });
            let baseUrl;
            try {
                baseUrl = new URL(url).origin;
            } catch {
                return reply.code(400).send({ error: "Invalid URL" });
            }
            const now = new Date().toISOString();
            if (!logs[baseUrl]) logs[baseUrl] = { count: 1, lastVisit: now };
            else {
                logs[baseUrl].count += 1;
                logs[baseUrl].lastVisit = now;
            }
            await fs.writeFile(LOG_FILE, JSON.stringify(logs, null, 2));
            return reply.code(200).send({ success: true, url: baseUrl, logs: logs[baseUrl] });
        }
    },
});
fastify.post("/scramjet/url", async (req, reply) => {
    try {
        const { url } = req.body;
        if (!url) return reply.code(400).send({ error: "Missing URL In Body" });
        await loadBlockedUrls();
        if (blockedUrls[url]) return reply.code(403).send(`<h1>Blocked</h1><p>${blockedUrls[url]}</p>`);
        let validatedUrl;
        try {
            validatedUrl = new URL(url);
        } catch {
            return reply.code(400).send({ error: "Invalid URL" });
        }
        await logUrlVisit(validatedUrl.toString());
        const response = await fetch(validatedUrl.toString());
        let body = await response.text();
        body = body.replace(
            /<meta[^>]+http-equiv=["']Content-Security-Policy["'][^>]*>/gi,
            ""
        );
        let contentType = response.headers.get("content-type") || "text/html";
        const headers = {};
        for (const [key, value] of response.headers.entries()) {
            const lower = key.toLowerCase();
            if (
                lower === "content-security-policy" ||
                lower === "content-security-policy-report-only" ||
                lower === "x-frame-options" ||
                lower === "frame-options" ||
                lower === "permissions-policy" ||
                lower === "cross-origin-opener-policy" ||
                lower === "cross-origin-embedder-policy"
            ) continue;
            headers[key] = value;
        }
        const baseUrl = validatedUrl.origin;
        body = body.replace(
            /<head([^>]*)>/i,
            `<head$1>
                <script>
                    (async () => {
                        if (!('serviceWorker' in navigator)) return;
                        let reg = await navigator.serviceWorker.register('/scram/sw.js', { scope: '/' });
                        await navigator.serviceWorker.ready;
                        if (!navigator.serviceWorker.controller) {
                            location.reload();
                            return;
                        }
                        const s = document.createElement("script");
                        s.src = "/scram/scramjet.all.js";
                        document.head.appendChild(s);
                    })();
                </script>
                <base href="${baseUrl}/">`
        );
        body = body.replace(/<head([^>]*)>/i, `<head$1><base href="${baseUrl}/">`);
        reply
        .code(response.status)
        .headers(headers)
        .header("Content-Type", contentType)
        .header(
            "Content-Security-Policy",
            `default-src * data: blob: 'unsafe-inline' 'unsafe-eval';
                script-src * data: blob: 'unsafe-inline' 'unsafe-eval';
                worker-src * blob:;
                connect-src *;
                img-src * data: blob:;
                frame-src *;
            style-src * 'unsafe-inline';`
        )
        .header(
            "Permissions-Policy",
            `
                geolocation=(),
                microphone=(),
                camera=(),
                payment=(),
                usb=(),
                serial=(),
                bluetooth=(),
                hid=(),
                clipboard-read=(),
                clipboard-write=(),
                web-share=(),
                fullscreen=(),
                display-capture=(),
                local-fonts=(),
                storage-access=(),
                window-management=(),
                file-system-access=(),
                idle-detection=(),
                publickey-credentials-get=()
            `.replace(/\s+/g, " ")
        )
        .send(body);
    } catch (err) {
        reply.code(500).send({ error: err.message });
    }
});
fastify.setNotFoundHandler((req, reply) => {
    return reply.code(404).type("text/html").sendFile("404.html");
});
function shutdown() {
    console.log("Closing Server");
    fastify.close();
    process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
scheduleDailyLogClear();
loadBlockedUrls();
cloneOrPullRepo().catch((err) => console.error("Initial Sync Failed:", err));
let port = parseInt(process.env.PORT || "");
if (isNaN(port)) port = 8080;
fastify.listen({ port, host: "0.0.0.0" }, () => {
    const address = fastify.server.address();
    console.log("Listening On:");
    console.log(`\thttp://localhost:${address.port}`);
    console.log(`\thttp://${hostname()}:${address.port}`);
    console.log(
        `\thttp://${address.family === "IPv6" ? `[${address.address}]` : address.address}:${
            address.port
        }`
    );
});
process.on("exit", (code) => {
    if (code === 137) {
        console.log("Restarting after OOM...");
        exec(`node src/index.js`);
    }
});