import fs from "fs";
import path from "path";
import { DATA_ROOT } from "./channelsstore.js";
export const BETA_DIR = path.join(DATA_ROOT, "betaapplicants");
export const BETA_REAPPLY_COOLDOWN_MS = 7 * 24 * 60 * 60 * 1000;
function ensureDir(dir) {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}
function entryPath(uid) {
    return path.join(BETA_DIR, String(uid), "data.json");
}
export function getBetaApplicant(uid) {
    try {
        const file = entryPath(uid);
        if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, "utf8"));
    } catch (e) {
        console.error(`[BetaStore] Failed To Read ${uid}:`, e.message);
    }
    return null;
}
export function saveBetaApplicant(uid, entry) {
    const file = entryPath(uid);
    ensureDir(path.dirname(file));
    fs.writeFileSync(file, JSON.stringify(entry, null, 2), "utf8");
}
export function listBetaApplicants(status = null) {
    ensureDir(BETA_DIR);
    const out = [];
    for (const d of fs.readdirSync(BETA_DIR, { withFileTypes: true })) {
        if (!d.isDirectory()) continue;
        const entry = getBetaApplicant(d.name);
        if (!entry) continue;
        if (status && entry.status !== status) continue;
        out.push(entry);
    }
    return out.sort((a, b) => (a.submittedAt || 0) - (b.submittedAt || 0));
}