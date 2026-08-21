import fs from "fs";
import path from "path";
import {
    DATA_ROOT,
    loadChannelsShape,
    saveChannelsShape,
    loadDiscordChannelMap as loadChannelDiscordMap,
    saveDiscordChannelMap as saveChannelDiscordMap,
    migrateLegacyChannelsData
} from "./channelsstore.js";
import { loadPrivateShape, savePrivateShape, migrateLegacyPrivateData } from "./privatestore.js";
import { loadPartnersShape, savePartnersShape, migrateLegacyPartnersData } from "./partnersstore.js";
function ensureDir(dir) {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}
function readJSON(file, fallback) {
    try {
        if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, "utf8"));
    } catch (e) {
        console.error(`[DataStore] Failed to read ${file}:`, e.message);
    }
    return fallback;
}
function writeJSON(file, data) {
    ensureDir(path.dirname(file));
    fs.writeFileSync(file, JSON.stringify(data, null, 2), "utf8");
}
const DONATIONS_PATH = path.join(DATA_ROOT, "donations", "data.json");
const NOTES_PATH = path.join(DATA_ROOT, "notes", "data.json");
const SITE_PATH = path.join(DATA_ROOT, "site", "data.json");
const UPDATES_PATH = path.join(DATA_ROOT, "updates", "data.json");
export const RESTRICTED_WORDS_PATH = path.join(DATA_ROOT, "restrictedwords", "data.json");
const ARTICLES_DIR = path.join(DATA_ROOT, "articles");
function loadArticlesShape() {
    ensureDir(ARTICLES_DIR);
    const entries = fs.readdirSync(ARTICLES_DIR, { withFileTypes: true })
        .filter(d => d.isDirectory())
        .map(d => d.name)
        .filter(n => /^\d+$/.test(n))
        .map(Number);
    if (entries.length === 0) return [];
    const max = Math.max(...entries);
    const articles = new Array(max + 1).fill(null);
    for (const n of entries) {
        articles[n] = readJSON(path.join(ARTICLES_DIR, String(n), "data.json"), null);
    }
    return articles;
}
function saveArticlesShape(articles = []) {
    ensureDir(ARTICLES_DIR);
    articles.forEach((article, i) => {
        if (article === null || article === undefined) return;
        writeJSON(path.join(ARTICLES_DIR, String(i), "data.json"), article);
    });
}
const NOTIFICATIONS_DIR = path.join(DATA_ROOT, "notifications");
function loadNotificationsAndPushTokensShape() {
    ensureDir(NOTIFICATIONS_DIR);
    const uids = fs.existsSync(NOTIFICATIONS_DIR)
        ? fs.readdirSync(NOTIFICATIONS_DIR, { withFileTypes: true }).filter(d => d.isDirectory()).map(d => d.name)
        : [];
    const notifications = {};
    const pushTokens = {};
    for (const uid of uids) {
        const tokens = readJSON(path.join(NOTIFICATIONS_DIR, uid, "tokens.json"), {});
        const settings = readJSON(path.join(NOTIFICATIONS_DIR, uid, "settings.json"), {});
        notifications[uid] = { settings, tokens };
        pushTokens[uid] = tokens;
    }
    return { notifications, pushTokens };
}
function saveNotificationsAndPushTokensShape(notifications = {}, pushTokens = {}) {
    const uids = new Set([...Object.keys(notifications), ...Object.keys(pushTokens)]);
    for (const uid of uids) {
        const dir = path.join(NOTIFICATIONS_DIR, uid);
        ensureDir(dir);
        const settings = notifications[uid]?.settings ?? {};
        const tokens = { ...(notifications[uid]?.tokens ?? {}), ...(pushTokens[uid] ?? {}) };
        writeJSON(path.join(dir, "settings.json"), settings);
        writeJSON(path.join(dir, "tokens.json"), tokens);
    }
}
export function loadFullData() {
    const { channels, messages, typing, pinned } = loadChannelsShape();
    const { private: privateData, metadata } = loadPrivateShape();
    const partners = loadPartnersShape();
    const { notifications, pushTokens } = loadNotificationsAndPushTokensShape();
    return {
        articles: loadArticlesShape(),
        channels,
        donations: readJSON(DONATIONS_PATH, { amount: 0 }),
        messages,
        metadata,
        notes: readJSON(NOTES_PATH, {}),
        partners,
        private: privateData,
        pushTokens,
        site: readJSON(SITE_PATH, {}),
        notifications,
        updates: readJSON(UPDATES_PATH, {}),
        typing,
        pinned
    };
}
export function saveFullData(data) {
    if (!data || typeof data !== "object") return;
    saveChannelsShape({
        channels: data.channels || {},
        messages: data.messages || {},
        typing: data.typing || {},
        pinned: data.pinned || {}
    });
    savePrivateShape({ private: data.private || {}, metadata: data.metadata || {} });
    savePartnersShape(data.partners || {});
    saveNotificationsAndPushTokensShape(data.notifications || {}, data.pushTokens || {});
    if (data.articles) saveArticlesShape(data.articles);
    writeJSON(DONATIONS_PATH, data.donations ?? { amount: 0 });
    writeJSON(NOTES_PATH, data.notes ?? {});
    writeJSON(SITE_PATH, data.site ?? {});
    writeJSON(UPDATES_PATH, data.updates ?? {});
}
export function loadRestrictedWordsFile() {
    return readJSON(RESTRICTED_WORDS_PATH, {});
}
export function saveRestrictedWordsFile(data) {
    writeJSON(RESTRICTED_WORDS_PATH, data || {});
}
export const loadDiscordChannelMap = loadChannelDiscordMap;
export const saveDiscordChannelMap = saveChannelDiscordMap;
export function migrateLegacyData(legacyData, { legacyAttachments = {}, legacyDiscordMap = {} } = {}) {
    const d = legacyData || {};
    migrateLegacyChannelsData({
        legacyChannels: d.channels || {},
        legacyMessages: d.messages || {},
        legacyTyping: d.typing || {},
        legacyPinned: d.pinned || {},
        legacyDiscordMap,
        legacyAttachments
    });
    migrateLegacyPrivateData({ legacyPrivate: d.private || {}, legacyMetadata: d.metadata || {} });
    migrateLegacyPartnersData(d.partners || {});
    saveNotificationsAndPushTokensShape(d.notifications || {}, d.pushTokens || {});
    if (Array.isArray(d.articles)) saveArticlesShape(d.articles);
    writeJSON(DONATIONS_PATH, d.donations ?? { amount: 0 });
    writeJSON(NOTES_PATH, d.notes ?? {});
    writeJSON(SITE_PATH, d.site ?? {});
    writeJSON(UPDATES_PATH, d.updates ?? {});
}