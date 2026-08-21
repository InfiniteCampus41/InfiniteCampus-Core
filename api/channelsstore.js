import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
export const DATA_ROOT = path.join(__dirname, "data");
export const CHANNELS_DIR = path.join(DATA_ROOT, "channels");
function ensureDir(dir) {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}
function safeChannelDirName(name) {
    const clean = String(name).replace(/[\/\\\0]/g, "_").trim();
    if (!clean || clean === "." || clean === "..") {
        throw new Error(`[ChannelsStore] Invalid channel name: ${JSON.stringify(name)}`);
    }
    return clean;
}
function channelDir(name) {
    return path.join(CHANNELS_DIR, safeChannelDirName(name));
}
function readJSON(file, fallback) {
    try {
        if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, "utf8"));
    } catch (e) {
        console.error(`[ChannelsStore] Failed to read ${file}:`, e.message);
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
function defaultMisc() {
    return {
        read: {},
        write: {},
        guestRead: false,
        guestWrite: false,
        typing: {},
        pinned: {},
        discordChannelId: null
    };
}
function defaultCache() {
    return {
        pendingEdits: {},
        pendingDeletes: {},
        pendingReacts: {},
        pendingUsernameChanges: {}
    };
}
export function listChannelNames() {
    ensureDir(CHANNELS_DIR);
    return fs.readdirSync(CHANNELS_DIR, { withFileTypes: true })
        .filter(d => d.isDirectory())
        .map(d => d.name);
}
export function ensureChannel(name) {
    ensureDir(channelDir(name));
}
export function getChannelMessages(name) {
    return readJSON(path.join(channelDir(name), "messages.json"), {});
}
export function saveChannelMessages(name, messages) {
    writeJSON(path.join(channelDir(name), "messages.json"), messages || {});
}
export function getChannelMisc(name) {
    return { ...defaultMisc(), ...readJSON(path.join(channelDir(name), "misc.json"), {}) };
}
export function saveChannelMisc(name, misc) {
    writeJSON(path.join(channelDir(name), "misc.json"), misc);
}
export function getChannelCache(name) {
    return { ...defaultCache(), ...readJSON(path.join(channelDir(name), "cache.json"), {}) };
}
export function saveChannelCache(name, cache) {
    writeJSON(path.join(channelDir(name), "cache.json"), cache);
}
export function getChannelAttachments(name) {
    return readJSON(path.join(channelDir(name), "attachments.json"), {});
}
export function saveChannelAttachments(name, attachments) {
    writeJSON(path.join(channelDir(name), "attachments.json"), attachments || {});
}
export function deleteChannel(name) {
    const dir = channelDir(name);
    if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
}
export function loadChannelsShape() {
    const names = listChannelNames();
    const channels = {}, messages = {}, typing = {}, pinned = {};
    for (const name of names) {
        const misc = getChannelMisc(name);
        channels[name] = {
            read: misc.read || {},
            write: misc.write || {},
            guestRead: !!misc.guestRead,
            guestWrite: !!misc.guestWrite
        };
        messages[name] = getChannelMessages(name);
        typing[name] = misc.typing || {};
        pinned[name] = misc.pinned || {};
    }
    return { channels, messages, typing, pinned };
}
export function saveChannelsShape({ channels = {}, messages = {}, typing = {}, pinned = {} }) {
    const names = new Set([
        ...Object.keys(channels),
        ...Object.keys(messages),
        ...Object.keys(typing),
        ...Object.keys(pinned),
        ...listChannelNames()
    ]);
    for (const name of names) {
        ensureChannel(name);
        const existingMisc = getChannelMisc(name);
        const chan = channels[name] || {};
        const misc = {
            ...existingMisc,
            read: chan.read ?? existingMisc.read ?? {},
            write: chan.write ?? existingMisc.write ?? {},
            guestRead: chan.guestRead ?? existingMisc.guestRead ?? false,
            guestWrite: chan.guestWrite ?? existingMisc.guestWrite ?? false,
            typing: typing[name] ?? {},
            pinned: pinned[name] ?? {}
        };
        saveChannelMisc(name, misc);
        saveChannelMessages(name, messages[name] ?? getChannelMessages(name));
    }
}
export function loadDiscordChannelMap() {
    const map = {};
    for (const name of listChannelNames()) {
        const misc = getChannelMisc(name);
        if (misc.discordChannelId) map[name] = misc.discordChannelId;
    }
    return map;
}
export function saveDiscordChannelMap(map) {
    for (const [name, discordChannelId] of Object.entries(map)) {
        ensureChannel(name);
        const misc = getChannelMisc(name);
        misc.discordChannelId = discordChannelId;
        saveChannelMisc(name, misc);
    }
    for (const name of listChannelNames()) {
        if (!(name in map)) {
            const misc = getChannelMisc(name);
            if (misc.discordChannelId) {
                misc.discordChannelId = null;
                saveChannelMisc(name, misc);
            }
        }
    }
}
export function loadAllAttachmentsFlat() {
    const flat = {};
    for (const name of listChannelNames()) {
        Object.assign(flat, getChannelAttachments(name));
    }
    return flat;
}
export function saveAllAttachmentsFlat(flatMap) {
    const byChannel = {};
    for (const [key, rec] of Object.entries(flatMap || {})) {
        const ch = rec?.websiteChannel || "_unknown";
        if (!byChannel[ch]) byChannel[ch] = {};
        byChannel[ch][key] = rec;
    }
    const allNames = new Set([...Object.keys(byChannel), ...listChannelNames()]);
    for (const name of allNames) {
        ensureChannel(name);
        saveChannelAttachments(name, byChannel[name] || {});
    }
}
export function migrateLegacyChannelsData({
    legacyChannels = {},
    legacyMessages = {},
    legacyTyping = {},
    legacyPinned = {},
    legacyDiscordMap = {},
    legacyAttachments = {}
} = {}) {
    ensureDir(CHANNELS_DIR);
    const names = new Set([
        ...Object.keys(legacyChannels),
        ...Object.keys(legacyMessages),
        ...Object.keys(legacyTyping),
        ...Object.keys(legacyPinned),
        ...Object.keys(legacyDiscordMap)
    ]);
    for (const name of names) {
        ensureChannel(name);
        const chan = legacyChannels[name] || {};
        const misc = {
            ...defaultMisc(),
            read: chan.read || {},
            write: chan.write || {},
            guestRead: !!chan.guestRead,
            guestWrite: !!chan.guestWrite,
            typing: legacyTyping[name] || {},
            pinned: legacyPinned[name] || {},
            discordChannelId: legacyDiscordMap[name] || null
        };
        saveChannelMisc(name, misc);
        saveChannelMessages(name, legacyMessages[name] || {});
        const cachePath = path.join(channelDir(name), "cache.json");
        if (!fs.existsSync(cachePath)) saveChannelCache(name, defaultCache());
    }
    if (legacyAttachments && Object.keys(legacyAttachments).length) {
        saveAllAttachmentsFlat(legacyAttachments);
    }
    return [...names];
}