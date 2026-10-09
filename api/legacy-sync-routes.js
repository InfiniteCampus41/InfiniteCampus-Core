import crypto from "crypto";
import express from "express";
export function attachLegacySyncRoutes(app, { getUsersCache, saveUsers, avatars = null }) {
    const SECRET = process.env.LEGACY_SYNC_SECRET || "";
    const guard = (req, res, next) => {
        if (!SECRET) return res.status(503).json({ error: "LEGACY_SYNC_SECRET is not set on the old server" });
        const got = Buffer.from(String(req.get("x-sync-secret") || ""));
        const want = Buffer.from(SECRET);
        if (got.length !== want.length || !crypto.timingSafeEqual(got, want)) return res.status(401).json({ error: "unauthorized" });
        next();
    };
    const stable = (v) => JSON.stringify(v, (k, x) => (x && typeof x === "object" && !Array.isArray(x) ? Object.fromEntries(Object.entries(x).sort()) : x));
    const hash = (u) => crypto.createHash("sha1").update(stable(u || {})).digest("hex");
    function applyPatch(uid, body) {
        const users = getUsersCache() || {};
        const user = users[uid] || { profile: {}, settings: {} };
        for (const part of ["profile", "settings"]) {
            const patch = body?.[part];
            if (!patch || typeof patch !== "object") continue;
            user[part] = { ...(user[part] || {}) };
            for (const [k, v] of Object.entries(patch)) {
                if (k === "__proto__" || k === "constructor") continue;
                if (v === null) delete user[part][k];
                else user[part][k] = v;
            }
        }
        users[uid] = user;
        saveUsers(users);
    }
    const validUid = (uid) => /^[A-Za-z0-9_-]{1,128}$/.test(uid);
    const subscribers = new Set();
    let known = new Map();
    let watcher = null;
    function scan(announce) {
        const users = getUsersCache() || {};
        const next = new Map();
        const changed = [];
        for (const [uid, u] of Object.entries(users)) {
            const h = hash(u);
            next.set(uid, h);
            if (announce && known.get(uid) !== h) changed.push(uid);
        }
        if (announce) for (const uid of known.keys()) if (!next.has(uid)) changed.push(uid);
        known = next;
        if (changed.length) {
            const payload = `event: change\ndata: ${JSON.stringify({ uids: changed.slice(0, 200) })}\n\n`;
            for (const res of subscribers) res.write(payload);
        }
    }
    function startWatcher() {
        if (watcher) return;
        scan(false);
        watcher = setInterval(() => {
            try {
                scan(true);
            } catch (err) {
                console.error("[legacy-sync] change scan failed:", err.message);
            }
        }, 2000);
    }
    function stopWatcherIfIdle() {
        if (subscribers.size || !watcher) return;
        clearInterval(watcher);
        watcher = null;
    }
    app.get("/internal/legacy-users/events", guard, (req, res) => {
        res.writeHead(200, {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache, no-transform",
            Connection: "keep-alive",
            "X-Accel-Buffering": "no",
        });
        res.write(": connected\n\n");
        subscribers.add(res);
        startWatcher();
        const ping = setInterval(() => res.write(": ping\n\n"), 15000);
        req.on("close", () => {
            clearInterval(ping);
            subscribers.delete(res);
            stopWatcherIfIdle();
        });
    });
    app.get("/internal/legacy-users/index", guard, (req, res) => {
        const users = getUsersCache() || {};
        const hashes = {};
        for (const [uid, u] of Object.entries(users)) hashes[uid] = hash(u);
        res.json({ hashes });
    });
    app.get("/internal/legacy-users", guard, (req, res) => res.json({ users: getUsersCache() || {} }));
    app.get("/internal/legacy-users/:uid", guard, (req, res) => {
        const u = (getUsersCache() || {})[req.params.uid];
        if (!u) return res.status(404).json({ error: "not found" });
        res.json({ user: u });
    });
    app.post("/internal/legacy-users/:uid", guard, (req, res) => {
        const uid = String(req.params.uid);
        if (!validUid(uid)) return res.status(400).json({ error: "bad uid" });
        applyPatch(uid, req.body);
        res.json({ ok: true });
    });
    if (avatars) {
        const EXT = { "image/png": ".png", "image/jpeg": ".jpg", "image/webp": ".webp" };
        app.get("/internal/legacy-users/:uid/avatar", guard, (req, res) => {
            const uid = String(req.params.uid);
            if (!validUid(uid)) return res.status(400).json({ error: "bad uid" });
            const pic = avatars.read(uid);
            if (!pic?.bytes?.length) return res.status(404).json({ error: "no picture" });
            res.set("Content-Type", pic.mime || "application/octet-stream");
            res.send(pic.bytes);
        });
        app.post("/internal/legacy-users/:uid/avatar", guard, express.raw({ type: "image/*", limit: "5mb" }), (req, res) => {
            const uid = String(req.params.uid);
            if (!validUid(uid)) return res.status(400).json({ error: "bad uid" });
            const ext = EXT[String(req.get("content-type") || "").split(";")[0].trim().toLowerCase()];
            if (!ext || !Buffer.isBuffer(req.body) || !req.body.length) return res.status(400).json({ error: "unsupported or empty image" });
            avatars.write(uid, req.body, ext);
            applyPatch(uid, { profile: { pic: Date.now() } });
            res.json({ ok: true });
        });
        app.delete("/internal/legacy-users/:uid/avatar", guard, (req, res) => {
            const uid = String(req.params.uid);
            if (!validUid(uid)) return res.status(400).json({ error: "bad uid" });
            avatars.remove(uid);
            applyPatch(uid, { profile: { pic: 0 } });
            res.json({ ok: true });
        });
    }
}