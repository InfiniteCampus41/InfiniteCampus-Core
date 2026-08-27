import fs from "fs";
import path from "path";
import crypto from "crypto";
import net from "net";
import { DATA_ROOT } from "./channelsstore.js";
const URLS_DIR = path.join(DATA_ROOT, "urls");
export const URLS_PATH = path.join(URLS_DIR, "urls.json");
function ensureDir(dir) {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}
const DEFAULT_SHAPE = { visited: {}, allowedHosts: [] };
export function loadUrlsFile() {
    ensureDir(URLS_DIR);
    if (!fs.existsSync(URLS_PATH)) {
        fs.writeFileSync(URLS_PATH, JSON.stringify(DEFAULT_SHAPE, null, 2), "utf8");
        return { visited: {}, allowedHosts: [] };
    }
    try {
        const raw = JSON.parse(fs.readFileSync(URLS_PATH, "utf8"));
        return {
            visited: raw?.visited && typeof raw.visited === "object" ? raw.visited : {},
            allowedHosts: Array.isArray(raw?.allowedHosts) ? raw.allowedHosts : []
        };
    } catch (e) {
        console.error("[UrlsStore] Failed To Read urls.json:", e.message);
        return { visited: {}, allowedHosts: [] };
    }
}
export function saveUrlsFile(data) {
    ensureDir(URLS_DIR);
    const shape = {
        visited: data?.visited && typeof data.visited === "object" ? data.visited : {},
        allowedHosts: Array.isArray(data?.allowedHosts) ? data.allowedHosts : []
    };
    fs.writeFileSync(URLS_PATH, JSON.stringify(shape, null, 2), "utf8");
    return shape;
}
export function isAllowedHost(hostname, allowedHosts = []) {
    if (!hostname) return false;
    const host = String(hostname).toLowerCase();
    for (const raw of allowedHosts) {
        if (typeof raw !== "string" || !raw.trim()) continue;
        const allowed = raw.trim().toLowerCase().replace(/^\.+/, "");
        if (!allowed) continue;
        if (host === allowed || host.endsWith(`.${allowed}`)) return true;
    }
    return false;
}
export function isLocalOrIpHost(hostname) {
    if (!hostname) return false;
    const host = String(hostname).toLowerCase();
    if (host === "localhost" || host.endsWith(".localhost")) return true;
    if (net.isIP(host)) return true;
    return false;
}
export function normalizeOrigin(rawUrl, { allowLocal = false } = {}) {
    let parsed;
    try {
        parsed = new URL(rawUrl);
    } catch {
        return null;
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
    if (!allowLocal && isLocalOrIpHost(parsed.hostname)) return null;
    return { origin: parsed.origin, hostname: parsed.hostname };
}
export function makeEntryId() {
    return crypto.randomBytes(6).toString("hex");
}