import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { loadAllAttachmentsFlat, saveAllAttachmentsFlat } from "./channelsstore.js";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REFRESH_BEFORE_EXPIRY_MS = 10 * 60 * 1000;
const CHECK_INTERVAL_MS = 5 * 60 * 1000;
const HEALTH_CHECK_INTERVAL_MS = 10 * 60 * 1000;
function loadAttachments() {
    try {
        return loadAllAttachmentsFlat();
    } catch (e) {
        console.error("[AttachmentTracker] Failed to load attachments:", e.message);
    }
    return {};
}
function saveAttachments(data) {
    try {
        saveAllAttachmentsFlat(data);
    } catch (e) {
        console.error("[AttachmentTracker] Failed to save attachments:", e.message);
    }
}
export function makeStableKey(channelId, messageId, filename) {
    return `${channelId}/${messageId}/${filename}`;
}
function parseCdnUrl(url) {
    try {
        const parsed = new URL(url);
        const host = parsed.hostname;
        const isDiscordCdn =
            host === "cdn.discordapp.com" ||
            host === "media.discordapp.net" ||
            host.endsWith(".discordapp.com") ||
            host.endsWith(".discordapp.net") ||
            host.endsWith(".discord.com");
        if (!isDiscordCdn) return null;
        const parts = parsed.pathname.split("/").filter(Boolean);
        if (parts[0] !== "attachments" || parts.length < 4) return null;
        const channelId = parts[1];
        const messageId = parts[2];
        const filename  = parts[3].split("?")[0];
        const exHex = parsed.searchParams.get("ex");
        let expiresAt = null;
        if (exHex) expiresAt = parseInt(exHex, 16) * 1000;
        return { channelId, messageId, filename, expiresAt };
    } catch {
        return null;
    }
}
function extractStableKeyProxyUrls(content) {
    if (!content || typeof content !== "string") return [];
    const results = [];
    const regex = /\/discord-media-proxy\?key=([^"'\s>]+)/g;
    let match;
    while ((match = regex.exec(content)) !== null) {
        try {
            const key = decodeURIComponent(match[1]);
            if (key.split("/").length >= 3) {
                results.push(key);
            }
        } catch {}
    }
    return results;
}
function extractLegacyCdnUrlsFromContent(content) {
    if (!content || typeof content !== "string") return [];
    const urls = [];
    const regex = /\/discord-media-proxy\?url=([^"'\s>]+)/g;
    let match;
    while ((match = regex.exec(content)) !== null) {
        try {
            const encodedInContent = match[1];
            const decoded = decodeURIComponent(encodedInContent);
            if (
                decoded.includes("cdn.discordapp.com/attachments/") ||
                decoded.includes("media.discordapp.net/attachments/")
            ) {
                urls.push({ decoded, encodedInContent });
            }
        } catch {}
    }
    return urls;
}
export function lookupCurrentUrl(stableKey) {
    const attachments = loadAttachments();
    const rec = attachments[stableKey];
    return rec?.currentUrl || null;
}
export function trackAttachmentsForMessage(websiteChannel, msgTimestamp, discordMsgId, content) {
    if (!discordMsgId || !content) return;
    const cdnUrls = extractLegacyCdnUrlsFromContent(content);
    if (cdnUrls.length === 0) return;
    const attachments = loadAttachments();
    let dirty = false;
    for (const { decoded: rawUrl } of cdnUrls) {
        const parsed = parseCdnUrl(rawUrl);
        if (!parsed) continue;
        const key = makeStableKey(parsed.channelId, parsed.messageId, parsed.filename);
        if (!attachments[key]) {
            attachments[key] = {
                discordMsgId,
                channelId:      parsed.channelId,
                messageId:      parsed.messageId,
                filename:       parsed.filename,
                expiresAt:      parsed.expiresAt,
                currentUrl:     rawUrl,
                websiteChannel,
                msgTimestamp:   Number(msgTimestamp),
            };
            dirty = true;
        } else {
            if (attachments[key].currentUrl !== rawUrl) {
                attachments[key].currentUrl = rawUrl;
                attachments[key].expiresAt  = parsed.expiresAt;
                dirty = true;
            }
        }
    }
    if (dirty) {
        saveAttachments(attachments);
        console.log(`[AttachmentTracker] Tracked ${cdnUrls.length} attachment(s) for msg ${discordMsgId} in #${websiteChannel}`);
    }
}
export function trackDiscordAttachments(websiteChannel, msgTimestamp, discordMsgId, discordAttachments) {
    if (!discordMsgId || !Array.isArray(discordAttachments) || discordAttachments.length === 0) return;
    const attachments = loadAttachments();
    let count = 0;
    for (const att of discordAttachments) {
        const rawUrl = att.url || att.proxy_url || "";
        if (!rawUrl) continue;
        const parsed = parseCdnUrl(rawUrl);
        if (!parsed) continue;
        const filename = (att.filename || parsed.filename).split("?")[0];
        const key = makeStableKey(parsed.channelId, parsed.messageId, filename);
        attachments[key] = {
            discordMsgId,
            channelId:      parsed.channelId,
            messageId:      parsed.messageId,
            filename,
            expiresAt:      parsed.expiresAt,
            currentUrl:     rawUrl,
            websiteChannel,
            msgTimestamp:   Number(msgTimestamp),
        };
        count++;
    }
    if (count > 0) {
        saveAttachments(attachments);
        console.log(`[AttachmentTracker] Tracked ${count} raw attachment(s) for msg ${discordMsgId} in #${websiteChannel}`);
    }
}
export function untrackAttachmentsForMessage(websiteChannel, msgTimestamp) {
    const attachments = loadAttachments();
    const ts = Number(msgTimestamp);
    const before = Object.keys(attachments).length;
    for (const key of Object.keys(attachments)) {
        const rec = attachments[key];
        if (rec.websiteChannel === websiteChannel && rec.msgTimestamp === ts) {
            delete attachments[key];
        }
    }
    if (Object.keys(attachments).length !== before) {
        saveAttachments(attachments);
    }
}
function migrateContentToStableKeys(content) {
    if (!content || typeof content !== "string") return content;
    const legacyUrls = extractLegacyCdnUrlsFromContent(content);
    if (legacyUrls.length === 0) return content;
    let updated = content;
    for (const { decoded, encodedInContent } of legacyUrls) {
        const parsed = parseCdnUrl(decoded);
        if (!parsed) continue;
        const stableKey = makeStableKey(parsed.channelId, parsed.messageId, parsed.filename);
        const encodedKey = encodeURIComponent(stableKey);
        const escapedOld = encodedInContent.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        updated = updated.replace(
            new RegExp(`\\/discord-media-proxy\\?url=${escapedOld}`, "g"),
            `/discord-media-proxy?key=${encodedKey}`
        );
    }
    return updated;
}
export async function scanAndRefreshExistingAttachments({ discordRequestForce, getDataCache, saveData, broadcastUpdate }) {
    console.log("[AttachmentTracker] Scanning existing messages for attachment URLs to refresh...");
    const data = getDataCache();
    const messagesRoot = data?.messages;
    if (!messagesRoot || typeof messagesRoot !== "object") {
        console.log("[AttachmentTracker] No messages found in data cache; skipping startup scan.");
        return;
    }
    const byMsg = new Map();
    for (const [websiteChannel, channelMsgs] of Object.entries(messagesRoot)) {
        if (!channelMsgs || typeof channelMsgs !== "object") continue;
        for (const [msgTimestamp, msgEntry] of Object.entries(channelMsgs)) {
            const content = msgEntry?.t;
            if (!content || typeof content !== "string") continue;
            const discordMsgId = msgEntry._discordId;
            if (!discordMsgId) continue;
            const legacyUrls = extractLegacyCdnUrlsFromContent(content);
            const stableKeys = extractStableKeyProxyUrls(content);
            if (legacyUrls.length === 0 && stableKeys.length === 0) continue;
            for (const { decoded: rawUrl, encodedInContent } of legacyUrls) {
                const parsed = parseCdnUrl(rawUrl);
                if (!parsed) continue;
                const { channelId, filename } = parsed;
                const msgKey = `${channelId}:${discordMsgId}`;
                if (!byMsg.has(msgKey)) {
                    byMsg.set(msgKey, {
                        channelId,
                        discordMsgId,
                        websiteChannel,
                        msgTimestamp: Number(msgTimestamp),
                        urls: new Map(),
                        hasLegacy: false,
                    });
                }
                byMsg.get(msgKey).urls.set(rawUrl, { filename, encodedInContent, isLegacy: true });
                byMsg.get(msgKey).hasLegacy = true;
            }
            for (const stableKey of stableKeys) {
                const parts = stableKey.split("/");
                if (parts.length < 3) continue;
                const channelId = parts[0];
                const filename  = parts[2];
                const msgKey = `${channelId}:${discordMsgId}`;
                if (!byMsg.has(msgKey)) {
                    byMsg.set(msgKey, {
                        channelId,
                        discordMsgId,
                        websiteChannel,
                        msgTimestamp: Number(msgTimestamp),
                        urls: new Map(),
                        hasLegacy: false,
                    });
                }
                byMsg.get(msgKey).urls.set(stableKey, { filename, isLegacy: false });
            }
        }
    }
    console.log(`[AttachmentTracker] Found ${byMsg.size} Discord message(s) with attachments to refresh.`);
    const attachments = loadAttachments();
    let totalRefreshed = 0;
    let totalMigrated = 0;
    for (const [, { channelId, discordMsgId, websiteChannel, msgTimestamp, urls, hasLegacy }] of byMsg.entries()) {
        let freshAttachments;
        try {
            const resp = await discordRequestForce({
                method: "get",
                url: `https://discord.com/api/v10/channels/${channelId}/messages/${discordMsgId}`,
            });
            freshAttachments = resp?.data?.attachments || [];
        } catch (e) {
            const status = e?.response?.status ?? e?.status ?? null;
            if (status === 404) {
                console.warn(`[AttachmentTracker] Startup scan: Discord msg ${discordMsgId} not found (deleted); removing stale entries.`);
                for (const [urlOrKey] of urls.entries()) delete attachments[urlOrKey];
            } else {
                console.error(`[AttachmentTracker] Startup scan: failed to fetch Discord msg ${discordMsgId} (status ${status}):`, e.message);
            }
            continue;
        }
        if (freshAttachments.length === 0) {
            for (const [urlOrKey] of urls.entries()) delete attachments[urlOrKey];
            continue;
        }
        const liveData = getDataCache();
        const msgEntry = liveData?.messages?.[websiteChannel]?.[String(msgTimestamp)];
        if (!msgEntry) continue;
        let updatedContent = msgEntry.t || "";
        let contentChanged = false;
        for (const [urlOrKey, { filename, isLegacy }] of urls.entries()) {
            const freshAtt =
                freshAttachments.find(a => (a.filename || "").split("?")[0] === filename) ||
                freshAttachments[0];
            if (!freshAtt) continue;
            const freshUrl = freshAtt.url || freshAtt.proxy_url;
            if (!freshUrl) continue;
            const parsedFresh = parseCdnUrl(freshUrl);
            const freshFilename = (freshAtt.filename || filename).split("?")[0];
            const freshChannelId = parsedFresh?.channelId || channelId;
            const freshMessageId = parsedFresh?.messageId || discordMsgId;
            const stableKey = makeStableKey(freshChannelId, freshMessageId, freshFilename);
            attachments[stableKey] = {
                discordMsgId,
                channelId:      freshChannelId,
                messageId:      freshMessageId,
                filename:       freshFilename,
                expiresAt:      parsedFresh?.expiresAt || null,
                currentUrl:     freshUrl,
                websiteChannel,
                msgTimestamp,
            };
            if (isLegacy) delete attachments[urlOrKey];
            totalRefreshed++;
            if (isLegacy) {
                const encodedKey = encodeURIComponent(stableKey);
                const escapedOld = urlOrKey.split("?")[0];
                const escapedOldEncoded = encodeURIComponent(escapedOld).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
                const proxyParamRegex = new RegExp(
                    `\\/discord-media-proxy\\?url=(${escapedOldEncoded}[^"'\\s>]*)`,
                    "g"
                );
                const before = updatedContent;
                updatedContent = updatedContent.replace(proxyParamRegex, () => {
                    return `/discord-media-proxy?key=${encodedKey}`;
                });
                if (updatedContent !== before) contentChanged = true;
            }
        }
        if (contentChanged) {
            msgEntry.t = updatedContent;
            liveData.messages[websiteChannel][String(msgTimestamp)] = msgEntry;
            saveData(liveData);
            broadcastUpdate(["messages", websiteChannel, String(msgTimestamp)], msgEntry);
            totalMigrated++;
        }
    }
    saveAttachments(attachments);
    console.log(`[AttachmentTracker] Startup scan complete: refreshed ${totalRefreshed} URL(s), migrated ${totalMigrated} message(s) to stable keys.`);
}
export function startAttachmentRefreshLoop({ discordRequestForce, getDataCache, saveData, broadcastUpdate }) {
    console.log("[AttachmentTracker] Starting attachment refresh loop");
    async function refreshExpired() {
        const attachments = loadAttachments();
        const now = Date.now();
        const toRefresh = [];
        for (const [key, rec] of Object.entries(attachments)) {
            if (!rec.expiresAt) continue;
            const timeUntilExpiry = rec.expiresAt - now;
            if (timeUntilExpiry <= REFRESH_BEFORE_EXPIRY_MS) {
                toRefresh.push({ key, rec });
            }
        }
        if (toRefresh.length === 0) return;
        console.log(`[AttachmentTracker] ${toRefresh.length} attachment(s) need expiry refresh`);
        const byMsg = new Map();
        for (const item of toRefresh) {
            const msgKey = `${item.rec.channelId}:${item.rec.discordMsgId}`;
            if (!byMsg.has(msgKey)) byMsg.set(msgKey, []);
            byMsg.get(msgKey).push(item);
        }
        for (const [, items] of byMsg.entries()) {
            const { channelId, discordMsgId, websiteChannel, msgTimestamp } = items[0].rec;
            let freshAttachments;
            try {
                const resp = await discordRequestForce({
                    method: "get",
                    url: `https://discord.com/api/v10/channels/${channelId}/messages/${discordMsgId}`,
                });
                freshAttachments = resp?.data?.attachments || [];
            } catch (e) {
                const status = e?.response?.status ?? e?.status ?? null;
                if (status === 404) {
                    console.warn(`[AttachmentTracker] Discord msg ${discordMsgId} not found (deleted); removing stale entries.`);
                    for (const { key } of items) delete attachments[key];
                } else {
                    console.error(`[AttachmentTracker] Failed to refresh Discord msg ${discordMsgId} (status ${status}):`, e.message);
                }
                continue;
            }
            if (freshAttachments.length === 0) {
                for (const { key } of items) delete attachments[key];
                continue;
            }
            for (const { key, rec } of items) {
                const freshAtt =
                    freshAttachments.find(a => (a.filename || "").split("?")[0] === rec.filename) ||
                    freshAttachments[0];
                if (!freshAtt) continue;
                const freshUrl = freshAtt.url || freshAtt.proxy_url;
                if (!freshUrl) continue;
                const parsedFresh = parseCdnUrl(freshUrl);
                attachments[key] = {
                    ...rec,
                    currentUrl: freshUrl,
                    expiresAt:  parsedFresh?.expiresAt || null,
                };
                console.log(`[AttachmentTracker] Refreshed URL for key ${key} in #${websiteChannel}`);
            }
        }
        saveAttachments(attachments);
    }
    async function healthCheckAttachments() {
        const attachments = loadAttachments();
        const keys = Object.keys(attachments);
        if (keys.length === 0) return;
        console.log(`[AttachmentTracker] Health check: verifying ${keys.length} attachment(s)...`);
        const toRefresh = new Map();
        for (const [key, rec] of Object.entries(attachments)) {
            if (!rec.currentUrl) continue;
            try {
                const r = await fetch(rec.currentUrl, {
                    method: "HEAD",
                    headers: { "User-Agent": "Mozilla/5.0" },
                    signal: AbortSignal.timeout(8000),
                });
                if (!r.ok) {
                    console.log(`[AttachmentTracker] Health check: attachment unreachable (${r.status}) — key=${key}`);
                    const msgKey = `${rec.channelId}:${rec.discordMsgId}`;
                    if (!toRefresh.has(msgKey)) toRefresh.set(msgKey, []);
                    toRefresh.get(msgKey).push({ key, rec });
                }
            } catch {
                console.log(`[AttachmentTracker] Health check: fetch error — key=${key}`);
                const msgKey = `${rec.channelId}:${rec.discordMsgId}`;
                if (!toRefresh.has(msgKey)) toRefresh.set(msgKey, []);
                toRefresh.get(msgKey).push({ key, rec });
            }
        }
        if (toRefresh.size === 0) {
            console.log("[AttachmentTracker] Health check: all attachments OK.");
            return;
        }
        console.log(`[AttachmentTracker] Health check: refreshing ${toRefresh.size} Discord message(s) with dead URLs...`);
        const freshAttachments2 = loadAttachments(); // reload to avoid clobbering concurrent changes
        for (const [, items] of toRefresh.entries()) {
            const { channelId, discordMsgId } = items[0].rec;
            let freshAtts;
            try {
                const resp = await fetch(
                    `https://discord.com/api/v10/channels/${channelId}/messages/${discordMsgId}`,
                    { headers: { Authorization: `Bot ${process.env.DISCORD_BOT_TOKEN}`, "User-Agent": "DiscordBot" } }
                );
                if (!resp.ok) throw Object.assign(new Error("HTTP " + resp.status), { status: resp.status });
                const json = await resp.json();
                freshAtts = json.attachments || [];
            } catch (e) {
                if (e.status === 404) {
                    for (const { key } of items) delete freshAttachments2[key];
                } else {
                    console.error(`[AttachmentTracker] Health check refresh failed for msg ${discordMsgId}:`, e.message);
                }
                continue;
            }
            if (freshAtts.length === 0) {
                for (const { key } of items) delete freshAttachments2[key];
                continue;
            }
            for (const { key, rec } of items) {
                const freshAtt =
                    freshAtts.find(a => (a.filename || "").split("?")[0] === rec.filename) ||
                    freshAtts[0];
                if (!freshAtt) continue;
                const freshUrl = freshAtt.url || freshAtt.proxy_url;
                if (!freshUrl) continue;
                const parsedFresh = parseCdnUrl(freshUrl);
                freshAttachments2[key] = {
                    ...rec,
                    currentUrl: freshUrl,
                    expiresAt:  parsedFresh?.expiresAt || null,
                };
                console.log(`[AttachmentTracker] Health check: refreshed key=${key}`);
            }
        }
        saveAttachments(freshAttachments2);
    }
    refreshExpired().catch(e => console.error("[AttachmentTracker] Refresh error:", e));
    setInterval(() => {
        refreshExpired().catch(e => console.error("[AttachmentTracker] Refresh error:", e));
    }, CHECK_INTERVAL_MS);
    healthCheckAttachments().catch(e => console.error("[AttachmentTracker] Health check error:", e));
    setInterval(() => {
        healthCheckAttachments().catch(e => console.error("[AttachmentTracker] Health check error:", e));
    }, HEALTH_CHECK_INTERVAL_MS);
}