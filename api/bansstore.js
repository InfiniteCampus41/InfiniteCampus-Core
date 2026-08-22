import fs from "fs";
import path from "path";
import { DATA_ROOT } from "./channelsstore.js";
export const BANS_DIR = path.join(DATA_ROOT, "bans");
function ensureDir(dir) {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}
function safeId(id) {
    const clean = String(id).replace(/[\/\\\0]/g, "_").trim();
    if (!clean || clean === "." || clean === "..") {
        throw new Error(`[BansStore] Invalid Ban Id: ${JSON.stringify(id)}`);
    }
    return clean;
}
function banDir(id) {
    return path.join(BANS_DIR, safeId(id));
}
function readJSON(file, fallback) {
    try {
        if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, "utf8"));
    } catch (e) {
        console.error(`[BansStore] Failed To Read ${file}:`, e.message);
    }
    return fallback;
}
function writeJSON(file, data) {
    ensureDir(path.dirname(file));
    fs.writeFileSync(file, JSON.stringify(data, null, 2), "utf8");
}
export function getBan(id) {
    if (!id) return null;
    let dir;
    try {
        dir = banDir(id);
    } catch {
        return null;
    }
    const file = path.join(dir, "data.json");
    const ban = readJSON(file, null);
    if (!ban) return null;
    if (ban.expiresAt && Date.now() >= ban.expiresAt) {
        unbanUser(id);
        return null;
    }
    return ban;
}
export function isBanned(id) {
    return !!getBan(id);
}
export function banUser(id, {
    reason = "",
    bannedBy = null,
    expiresAt = null,
    recentMessages = [],
    type = "user",
    displayName = null
} = {}) {
    ensureDir(banDir(id));
    const ban = {
        id: String(id),
        type,
        displayName,
        reason: String(reason || "").slice(0, 500),
        bannedBy,
        bannedAt: Date.now(),
        expiresAt: expiresAt || null,
        recentMessages: Array.isArray(recentMessages) ? recentMessages.slice(-10) : []
    };
    writeJSON(path.join(banDir(id), "data.json"), ban);
    return ban;
}
export function unbanUser(id) {
    let dir;
    try {
        dir = banDir(id);
    } catch {
        return false;
    }
    if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
    return true;
}
export function listBans() {
    ensureDir(BANS_DIR);
    return fs.readdirSync(BANS_DIR, { withFileTypes: true })
        .filter(d => d.isDirectory())
        .map(d => getBan(d.name))
        .filter(Boolean);
}