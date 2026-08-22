import fs from "fs";
import path from "path";
import { DATA_ROOT } from "./channelsstore.js";
export const PARTNERS_DIR = path.join(DATA_ROOT, "partners");
const INDEX_PATH = path.join(PARTNERS_DIR, "_index.json");
function ensureDir(dir) {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}
function readJSON(file, fallback) {
    try {
        if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, "utf8"));
    } catch (e) {
        console.error(`[PartnersStore] Failed to read ${file}:`, e.message);
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
    _index = readJSON(INDEX_PATH, { nextId: 1, partners: {} });
    if (!_index.partners) _index.partners = {};
    if (!_index.nextId) _index.nextId = 1;
    return _index;
}
function saveIndex() {
    writeJSON(INDEX_PATH, _index);
}
export function partnerDir(id) {
    return path.join(PARTNERS_DIR, String(id));
}
export function getOrCreatePartnerId(uid, name) {
    const idx = loadIndex();
    for (const [id, p] of Object.entries(idx.partners)) {
        if (p.uid === uid && p.name === name) return id;
    }
    const id = String(idx.nextId++);
    idx.partners[id] = { uid, name };
    ensureDir(partnerDir(id));
    saveIndex();
    return id;
}
export function findPartnerImageFile(id) {
    const dir = partnerDir(id);
    if (!fs.existsSync(dir)) return null;
    const match = fs.readdirSync(dir).find(name => /^image\.[a-z0-9]+$/i.test(name));
    return match ? path.join(dir, match) : null;
}
export function deletePartnerImageFiles(id) {
    const dir = partnerDir(id);
    if (!fs.existsSync(dir)) return;
    for (const name of fs.readdirSync(dir)) {
        if (/^image\.[a-z0-9]+$/i.test(name)) {
            fs.rmSync(path.join(dir, name), { force: true });
        }
    }
}
export function loadPartnersShape() {
    const idx = loadIndex();
    const partners = {};
    for (const [id, p] of Object.entries(idx.partners)) {
        const filePath = path.join(partnerDir(id), "data.json");
        const data = readJSON(filePath, undefined);
        if (!partners[p.uid]) partners[p.uid] = {};
        if (data === undefined || data === null) {
            partners[p.uid][p.name] = null;
        } else {
            partners[p.uid][p.name] = {
                desc: data.desc ?? null,
                link: data.link ?? null,
                photo: data.photo ?? null
            };
        }
    }
    return partners;
}
export function savePartnersShape(partners = {}) {
    for (const [uid, byName] of Object.entries(partners || {})) {
        if (!byName || typeof byName !== "object") continue;
        for (const [name, info] of Object.entries(byName)) {
            const id = getOrCreatePartnerId(uid, name);
            if (info === null || info === undefined) {
                writeJSON(path.join(partnerDir(id), "data.json"), null);
            } else {
                writeJSON(path.join(partnerDir(id), "data.json"), {
                    id,
                    uid,
                    name,
                    desc: info?.desc ?? null,
                    link: info?.link ?? null,
                    photo: info?.photo ?? null
                });
            }
        }
    }
}
export function migrateLegacyPartnersData(legacyPartners = {}) {
    ensureDir(PARTNERS_DIR);
    savePartnersShape(legacyPartners);
    return Object.keys(loadIndex().partners);
}