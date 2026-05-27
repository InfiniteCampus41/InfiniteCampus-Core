import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ATTACHMENTS_PATH = path.join(__dirname, "attachments.json");
const REFRESH_BEFORE_EXPIRY_MS = 10 * 60 * 1000;
const CHECK_INTERVAL_MS = 5 * 60 * 1000;
function loadAttachments() {
    try {
        if (fs.existsSync(ATTACHMENTS_PATH)) {
            return JSON.parse(fs.readFileSync(ATTACHMENTS_PATH, "utf8"));
        }
    } catch (e) {
        console.error("[AttachmentTracker] Failed to load attachments.json:", e.message);
    }
    return {};
}
function saveAttachments(data) {
    try {
        fs.writeFileSync(ATTACHMENTS_PATH, JSON.stringify(data, null, 2), "utf8");
    } catch (e) {
        console.error("[AttachmentTracker] Failed to save attachments.json:", e.message);
    }
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
        if (exHex) {
            expiresAt = parseInt(exHex, 16) * 1000;
        }
        return { channelId, messageId, filename, expiresAt };
    } catch {
        return null;
    }
}
function extractCdnUrlsFromContent(content) {
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
/**
 * @param {string} websiteChannel
 * @param {number} msgTimestamp
 * @param {string} discordMsgId
 * @param {string} content
 */
export function trackAttachmentsForMessage(websiteChannel, msgTimestamp, discordMsgId, content) {
    if (!discordMsgId || !content) return;
    const cdnUrls = extractCdnUrlsFromContent(content);
    if (cdnUrls.length === 0) return;
    const attachments = loadAttachments();
    let dirty = false;
    for (const { decoded: rawUrl } of cdnUrls) {
        const parsed = parseCdnUrl(rawUrl);
        if (!parsed) continue;
        const key = rawUrl;
        attachments[key] = {
            discordMsgId,
            channelId:      parsed.channelId,
            filename:       parsed.filename,
            expiresAt:      parsed.expiresAt,
            websiteChannel,
            msgTimestamp:   Number(msgTimestamp),
            rawUrl,
        };
        dirty = true;
    }
    if (dirty) {
        saveAttachments(attachments);
        console.log(`[AttachmentTracker] Tracked ${cdnUrls.length} attachment(s) for msg ${discordMsgId} in #${websiteChannel}`);
    }
}
/**
 * @param {string} websiteChannel
 * @param {number} msgTimestamp
 * @param {string} discordMsgId
 * @param {Array<{url: string, proxy_url?: string, filename?: string}>} discordAttachments
 */
export function trackDiscordAttachments(websiteChannel, msgTimestamp, discordMsgId, discordAttachments) {
    if (!discordMsgId || !Array.isArray(discordAttachments) || discordAttachments.length === 0) return;
    const attachments = loadAttachments();
    let count = 0;
    for (const att of discordAttachments) {
        const rawUrl = att.url || att.proxy_url || "";
        if (!rawUrl) continue;
        const parsed = parseCdnUrl(rawUrl);
        if (!parsed) continue;
        const filename = att.filename || parsed.filename;
        attachments[rawUrl] = {
            discordMsgId,
            channelId:      parsed.channelId,
            filename,
            expiresAt:      parsed.expiresAt,
            websiteChannel,
            msgTimestamp:   Number(msgTimestamp),
            rawUrl,
        };
        count++;
    }
    if (count > 0) {
        saveAttachments(attachments);
        console.log(`[AttachmentTracker] Tracked ${count} raw attachment(s) for msg ${discordMsgId} in #${websiteChannel}`);
    }
}
/**
 * @param {string} websiteChannel
 * @param {number} msgTimestamp
 */
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
/**
 * @param {object} deps
 * @param {Function} deps.discordRequestForce
 * @param {Function} deps.getDataCache
 * @param {Function} deps.saveData
 * @param {Function} deps.broadcastUpdate
 */
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
            const cdnUrls = extractCdnUrlsFromContent(content);
            if (cdnUrls.length === 0) continue;
            const discordMsgId = msgEntry._discordId;
            if (!discordMsgId) continue;
            for (const { decoded: rawUrl, encodedInContent } of cdnUrls) {
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
                    });
                }
                byMsg.get(msgKey).urls.set(rawUrl, { filename, encodedInContent });
            }
        }
    }
    if (byMsg.size === 0) {
        console.log("[AttachmentTracker] No attachment URLs found in existing messages.");
        return;
    }
    console.log(`[AttachmentTracker] Found ${byMsg.size} Discord message(s) with attachments to refresh.`);
    const attachments = loadAttachments();
    let totalRefreshed = 0;
    let totalChanged = 0;
    for (const [, { channelId, discordMsgId, websiteChannel, msgTimestamp, urls }] of byMsg.entries()) {
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
                for (const rawUrl of urls.keys()) delete attachments[rawUrl];
            } else {
                console.error(`[AttachmentTracker] Startup scan: failed to fetch Discord msg ${discordMsgId} (status ${status}):`, e.message);
            }
            continue;
        }
        if (freshAttachments.length === 0) {
            for (const rawUrl of urls.keys()) delete attachments[rawUrl];
            continue;
        }
        const liveData = getDataCache();
        const msgEntry = liveData?.messages?.[websiteChannel]?.[String(msgTimestamp)];
        if (!msgEntry) continue;
        let updatedContent = msgEntry.t || "";
        let contentChanged = false;
        for (const [rawUrl, { filename }] of urls.entries()) {
            const freshAtt =
                freshAttachments.find(a => {
                    const fname = (a.filename || "").split("?")[0];
                    return fname === filename;
                }) || freshAttachments[0];
            if (!freshAtt) continue;
            const freshUrl = freshAtt.url || freshAtt.proxy_url;
            if (!freshUrl) continue;
            const newEncoded = encodeURIComponent(freshUrl);
            const pathKey = encodeURIComponent(rawUrl.split("?")[0]);
            const proxyParamRegex = new RegExp(
                `(\/discord-media-proxy\?url=)(${pathKey.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}[^"'\s>]*)`,
                "g"
            );
            const before = updatedContent;
            updatedContent = updatedContent.replace(proxyParamRegex, (_, prefix, _oldEncoded) => {
                return prefix + newEncoded;
            });
            if (updatedContent !== before) contentChanged = true;
            const parsedFresh = parseCdnUrl(freshUrl);
            attachments[freshUrl] = {
                discordMsgId,
                channelId,
                filename: freshAtt.filename || filename,
                expiresAt: parsedFresh?.expiresAt || null,
                websiteChannel,
                msgTimestamp,
                rawUrl: freshUrl,
            };
            if (freshUrl !== rawUrl) delete attachments[rawUrl];
            totalRefreshed++;
        }
        if (contentChanged) {
            msgEntry.t = updatedContent;
            liveData.messages[websiteChannel][String(msgTimestamp)] = msgEntry;
            saveData(liveData);
            broadcastUpdate(["messages", websiteChannel, String(msgTimestamp)], msgEntry);
            totalChanged++;
        }
    }
    saveAttachments(attachments);
    console.log(`[AttachmentTracker] Startup scan complete: refreshed ${totalRefreshed} URL(s) across ${totalChanged} message(s).`);
}
/**
 * @param {object} deps
 * @param {Function} deps.discordRequestForce
 * @param {Function} deps.getDataCache
 * @param {Function} deps.saveData
 * @param {Function} deps.broadcastUpdate
 */
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
        console.log(`[AttachmentTracker] ${toRefresh.length} attachment(s) need refresh`);
        const byMsg = new Map();
        for (const item of toRefresh) {
            const msgKey = `${item.rec.channelId}:${item.rec.discordMsgId}`;
            if (!byMsg.has(msgKey)) byMsg.set(msgKey, []);
            byMsg.get(msgKey).push(item);
        }
        for (const [msgKey, items] of byMsg.entries()) {
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
            const data = getDataCache();
            const msgEntry = data?.messages?.[websiteChannel]?.[String(msgTimestamp)];
            if (!msgEntry) {
                for (const { key } of items) delete attachments[key];
                continue;
            }
            let contentChanged = false;
            let updatedContent = msgEntry.t || "";
            for (const { key, rec } of items) {
                const freshAtt = freshAttachments.find(a => {
                    const fname = (a.filename || "").split("?")[0];
                    return fname === rec.filename;
                }) || freshAttachments[0];
                if (!freshAtt) continue;
                const freshUrl = freshAtt.url || freshAtt.proxy_url;
                if (!freshUrl || freshUrl === rec.rawUrl) continue;
                const oldEncoded = encodeURIComponent(rec.rawUrl);
                const newEncoded = encodeURIComponent(freshUrl);
                if (updatedContent.includes(oldEncoded)) {
                    updatedContent = updatedContent.split(oldEncoded).join(newEncoded);
                    contentChanged = true;
                }
                const parsedFresh = parseCdnUrl(freshUrl);
                const newExpiresAt = parsedFresh?.expiresAt || null;
                delete attachments[key];
                attachments[freshUrl] = {
                    ...rec,
                    rawUrl:    freshUrl,
                    expiresAt: newExpiresAt,
                };
                console.log(`[AttachmentTracker] Refreshed attachment URL for msg ${discordMsgId} in #${websiteChannel}`);
            }
            if (contentChanged) {
                msgEntry.t = updatedContent;
                data.messages[websiteChannel][String(msgTimestamp)] = msgEntry;
                saveData(data);
                broadcastUpdate(["messages", websiteChannel, String(msgTimestamp)], msgEntry);
                console.log(`[AttachmentTracker] Updated message content for ts=${msgTimestamp} in #${websiteChannel}`);
            }
        }
        saveAttachments(attachments);
    }
    refreshExpired().catch(e => console.error("[AttachmentTracker] Refresh error:", e));
    setInterval(() => {
        refreshExpired().catch(e => console.error("[AttachmentTracker] Refresh error:", e));
    }, CHECK_INTERVAL_MS);
}