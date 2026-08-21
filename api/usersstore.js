import fs from "fs";
import path from "path";
import { DATA_ROOT } from "./channelsstore.js";
export const USERS_DIR = path.join(DATA_ROOT, "users");
function ensureDir(dir) {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}
function readJSON(file, fallback) {
    try {
        if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, "utf8"));
    } catch (e) {
        console.error(`[UsersStore] Failed to read ${file}:`, e.message);
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
function userDir(uid) {
    return path.join(USERS_DIR, String(uid));
}
const ROLE_FIELDS = [
    "isOwner", "isTester", "isCoOwner", "isHAdmin", "isAdmin", "isDev", "isUploader",
    "premium3", "premium2", "premium1", "mileStone", "isPartner", "verified", "isSus",
    "isDonater", "isGuesser", "isLink", "blocksi", "guardian", "lanschool", "linewize",
    "secure", "fortiguard", "lightspeed", "cisco", "contentkeeper", "deledao", "iboss",
    "barracuda"
];
const SETTINGS_FIELDS = ["color", "showMentions", "userEmail", "betterWeather", "theme", "themePreference"];
function splitProfile(profile = {}) {
    const roles = {};
    const data = {};
    for (const [k, v] of Object.entries(profile || {})) {
        if (ROLE_FIELDS.includes(k)) roles[k] = v;
        else if (SETTINGS_FIELDS.includes(k)) continue;
        else data[k] = v;
    }
    return { roles, data };
}
function mergeSettings(profile = {}, settings = {}) {
    const merged = { ...settings };
    for (const k of SETTINGS_FIELDS) {
        if (merged[k] === undefined && profile[k] !== undefined) merged[k] = profile[k];
    }
    return merged;
}
export function listUserIds() {
    ensureDir(USERS_DIR);
    return fs.readdirSync(USERS_DIR, { withFileTypes: true })
        .filter(d => d.isDirectory())
        .map(d => d.name);
}
export function loadUsersShape() {
    const users = {};
    for (const uid of listUserIds()) {
        const roles = readJSON(path.join(userDir(uid), "profile", "roles.json"), {});
        const data = readJSON(path.join(userDir(uid), "profile", "data.json"), {});
        const settings = readJSON(path.join(userDir(uid), "settings", "data.json"), {});
        users[uid] = { profile: { ...roles, ...data }, settings };
    }
    return users;
}
export function saveUsersShape(users = {}) {
    const keepIds = new Set(Object.keys(users || {}));
    for (const uid of listUserIds()) {
        if (!keepIds.has(uid)) fs.rmSync(userDir(uid), { recursive: true, force: true });
    }
    for (const [uid, user] of Object.entries(users || {})) {
        const profile = user?.profile || {};
        const settingsIn = user?.settings || {};
        const { roles, data } = splitProfile(profile);
        const settings = mergeSettings(profile, settingsIn);
        writeJSON(path.join(userDir(uid), "profile", "roles.json"), roles);
        writeJSON(path.join(userDir(uid), "profile", "data.json"), data);
        writeJSON(path.join(userDir(uid), "settings", "data.json"), settings);
    }
}
export function migrateLegacyUsersData(legacyUsers = {}) {
    ensureDir(USERS_DIR);
    saveUsersShape(legacyUsers);
    return listUserIds();
}