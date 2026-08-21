import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { DATA_ROOT } from "./channelsstore.js";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
export const PRIVATE_DIR = path.join(DATA_ROOT, "private");
const INDEX_PATH = path.join(PRIVATE_DIR, "_index.json");
function ensureDir(dir) {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}
function readJSON(file, fallback) {
    try {
        if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, "utf8"));
    } catch (e) {
        console.error(`[PrivateStore] Failed to read ${file}:`, e.message);
    }
    return fallback;
}
function stripNulls(value) {
    if (Array.isArray(value)) return value.map(stripNulls);
    if (value && typeof value === "object") {
        const result = {};
        for (const [k, v] of Object.entries(value)) {
            if (v === null) continue;
            result[k] = stripNulls(v);
        }
        return result;
    }
    return value;
}
function writeJSON(file, data) {
    ensureDir(path.dirname(file));
    fs.writeFileSync(file, JSON.stringify(stripNulls(data), null, 2), "utf8");
}
let _index = null;
function loadIndex() {
    if (_index) return _index;
    _index = readJSON(INDEX_PATH, { nextId: 1, chats: {} });
    if (!_index.chats) _index.chats = {};
    if (!_index.nextId) _index.nextId = 1;
    return _index;
}
function saveIndex() {
    writeJSON(INDEX_PATH, _index);
}

function chatDir(id) {
    return path.join(PRIVATE_DIR, String(id));
}
function getOrCreateChatId(uidA, uidB) {
    const idx = loadIndex();
    for (const [id, pair] of Object.entries(idx.chats)) {
        if ((pair.uidA === uidA && pair.uidB === uidB) || (pair.uidA === uidB && pair.uidB === uidA)) {
            return { id, uidA: pair.uidA, uidB: pair.uidB };
        }
    }
    const id = String(idx.nextId++);
    idx.chats[id] = { uidA, uidB };
    ensureDir(chatDir(id));
    saveIndex();
    return { id, uidA, uidB };
}
export function loadPrivateShape() {
    const idx = loadIndex();
    const privateData = {};
    const metadata = {};
    for (const [id, pair] of Object.entries(idx.chats)) {
        const { uidA, uidB } = pair;
        const messages = readJSON(path.join(chatDir(id), "messages.json"), {});
        if (!privateData[uidA]) privateData[uidA] = {};
        privateData[uidA][uidB] = messages;
        const meta = readJSON(path.join(chatDir(id), "metadata.json"), {});
        for (const uid of [uidA, uidB]) {
            const other = uid === uidA ? uidB : uidA;
            if (meta[uid]) {
                if (!metadata[uid]) metadata[uid] = { privateChats: {} };
                metadata[uid].privateChats[other] = meta[uid];
            }
        }
    }
    return { private: privateData, metadata };
}
export function savePrivateShape({ private: privateData = {}, metadata = {} }) {
    for (const [uidA, others] of Object.entries(privateData || {})) {
        if (!others || typeof others !== "object") continue;
        for (const [uidB, messages] of Object.entries(others)) {
            const { id } = getOrCreateChatId(uidA, uidB);
            ensureDir(chatDir(id));
            writeJSON(path.join(chatDir(id), "messages.json"), messages || {});
        }
    }
    for (const [uid, userMeta] of Object.entries(metadata || {})) {
        const chats = userMeta?.privateChats || {};
        for (const [otherUid, entry] of Object.entries(chats)) {
            const { id } = getOrCreateChatId(uid, otherUid);
            const metaPath = path.join(chatDir(id), "metadata.json");
            const existing = readJSON(metaPath, {});
            existing[uid] = entry;
            writeJSON(metaPath, existing);
        }
    }
    const idx = loadIndex();
    for (const id of Object.keys(idx.chats)) {
        const miscPath = path.join(chatDir(id), "misc.json");
        if (!fs.existsSync(miscPath)) writeJSON(miscPath, {});
    }
}
export function migrateLegacyPrivateData({ legacyPrivate = {}, legacyMetadata = {} } = {}) {
    ensureDir(PRIVATE_DIR);
    savePrivateShape({ private: legacyPrivate, metadata: legacyMetadata });
    return Object.keys(loadIndex().chats);
}