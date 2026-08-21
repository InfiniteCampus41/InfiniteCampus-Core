import fs from "fs";
import path from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";
import { DATA_ROOT } from "./channelsstore.js";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
export const GROUPS_DIR = path.join(DATA_ROOT, "groups");
export const GROUPS_JSON_PATH = path.join(GROUPS_DIR, "data.json");
export const MAX_GROUP_MEMBERS = 20;
export const MAX_REACTIONS_PER_MSG = 5;
export const MAX_REACTIONS_PER_USER_MSG = 20;
const INVITE_CODE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_";
const INVITE_CODE_LENGTH = 12;
const DEFAULT_HOST_URL = "https://www.infinitecampus.xyz";
const ALLOWED_HOST_URLS = [
    "https://www.infinitecampus.xyz",
    "https://instructure.space",
    "https://backup.infinitecampus.xyz",
    "https://backup.instructure.space"
];
export function resolveHostUrl(req) {
    let host = "";
    try {
        host = (req?.headers?.host || (typeof req?.get === "function" ? req.get("host") : "") || "")
            .toString()
            .toLowerCase()
            .split(":")[0];
    } catch {
        host = "";
    }
    const match = ALLOWED_HOST_URLS.find(u => {
        try {
            return new URL(u).hostname.toLowerCase() === host;
        } catch {
            return false;
        }
    });
    return match || DEFAULT_HOST_URL;
}
let _cache = null;
function ensureDir(dir) {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}
function groupDir(id) {
    return path.join(GROUPS_DIR, String(id));
}
function readJSON(file, fallback) {
    try {
        if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, "utf8"));
    } catch (e) {
        console.error(`[Groups] Failed To Read ${file}:`, e.message);
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
function defaultData() {
    return { nextId: 1, groups: {} };
}
export function loadGroups() {
    if (_cache) return _cache;
    try {
        ensureDir(GROUPS_DIR);
        const meta = readJSON(GROUPS_JSON_PATH, null);
        const ids = fs.readdirSync(GROUPS_DIR, { withFileTypes: true })
            .filter(d => d.isDirectory())
            .map(d => d.name);
        const groups = {};
        for (const id of ids) {
            const base = readJSON(path.join(groupDir(id), "data.json"), null);
            if (!base) continue;
            const messages = readJSON(path.join(groupDir(id), "messages.json"), {});
            groups[String(id)] = { ...base, messages };
        }
        let nextId = meta?.nextId;
        if (!nextId) {
            const maxId = Math.max(0, ...Object.keys(groups).map(Number).filter(n => !isNaN(n)));
            nextId = maxId + 1;
        }
        _cache = { nextId, groups };
        return _cache;
    } catch (e) {
        console.error("[Groups] Failed To Load Groups:", e.message);
    }
    _cache = defaultData();
    return _cache;
}
export function saveGroups(data) {
    _cache = data;
    try {
        ensureDir(GROUPS_DIR);
        writeJSON(GROUPS_JSON_PATH, { nextId: data.nextId });
        const keepIds = new Set(Object.keys(data.groups || {}));
        const existingIds = fs.readdirSync(GROUPS_DIR, { withFileTypes: true })
            .filter(d => d.isDirectory())
            .map(d => d.name);
        for (const id of existingIds) {
            if (!keepIds.has(id)) fs.rmSync(groupDir(id), { recursive: true, force: true });
        }
        for (const [id, group] of Object.entries(data.groups || {})) {
            ensureDir(groupDir(id));
            const { messages, ...rest } = group;
            writeJSON(path.join(groupDir(id), "data.json"), rest);
            writeJSON(path.join(groupDir(id), "messages.json"), messages || {});
            const miscPath = path.join(groupDir(id), "misc.json");
            if (!fs.existsSync(miscPath)) writeJSON(miscPath, {});
        }
    } catch (e) {
        console.error("[Groups] Failed To Save Groups:", e.message);
    }
}
export function migrateLegacyGroupsData(legacy) {
    if (!legacy || typeof legacy !== "object") return;
    _cache = null;
    saveGroups({ nextId: legacy.nextId || 1, groups: legacy.groups || {} });
}
export function generateInviteCode() {
    let code = "";
    const bytes = crypto.randomBytes(INVITE_CODE_LENGTH);
    for (let i = 0; i < INVITE_CODE_LENGTH; i++) {
        code += INVITE_CODE_CHARS[bytes[i] % INVITE_CODE_CHARS.length];
    }
    return code;
}
function welcomeMessageText(groupName, inviteCode, hostUrl) {
    return `Welcome to ${groupName}! This is the beginning of this channel.\nYou can invite more people into your group by sharing the link below:\nInvite Code: ${inviteCode}\nInvite Link: https://www.infinitecampus.xyz/join/${inviteCode}\nSecond Invite Link: https://instructure.space/join/${inviteCode}`;
}
export function getGroup(id) {
    const data = loadGroups();
    return data.groups[String(id)] || null;
}
export function getGroupByInvite(inviteCode) {
    const data = loadGroups();
    for (const g of Object.values(data.groups)) {
        if (g.inviteCode === inviteCode) return g;
    }
    return null;
}
export function isMember(group, uid) {
    return !!group && Array.isArray(group.members) && group.members.includes(uid);
}
export function isOwner(group, uid) {
    return !!group && group.ownerUid === uid;
}
export function getUserGroups(uid) {
    const data = loadGroups();
    return Object.values(data.groups)
        .filter(g => isMember(g, uid))
        .map(g => stripMessagesForList(g, uid));
}
function stripMessagesForList(group, uid) {
    const { messages, lastRead, ...rest } = group;
    const msgKeys = messages ? Object.keys(messages) : [];
    let lastMessage = null;
    if (msgKeys.length) {
        const lastKey = msgKeys.sort((a, b) => Number(a) - Number(b)).pop();
        lastMessage = { ts: lastKey, ...messages[lastKey] };
    }
    let unread = false;
    if (uid && lastMessage) {
        const readAt = (lastRead && lastRead[uid]) || 0;
        unread = Number(lastMessage.ts) > readAt;
    }
    return { ...rest, lastMessage, messageCount: msgKeys.length, unread };
}
export function createGroup(name, ownerUid, hostUrl) {
    const data = loadGroups();
    const id = data.nextId;
    data.nextId = id + 1;
    const inviteCode = generateInviteCode();
    const createdAt = Date.now();
    const welcomeMsgId = String(createdAt);
    const group = {
        id,
        name: String(name).slice(0, 60),
        ownerUid,
        members: [ownerUid],
        inviteCode,
        inviteLink: `${hostUrl}/join/${inviteCode}`,
        createdAt,
        lastRead: { [ownerUid]: createdAt },
        messages: {
            [welcomeMsgId]: {
                t: welcomeMessageText(name, inviteCode, hostUrl),
                s: "K8DFw6au2sMLN0LvCo4T1A5quu43",
                timestamp: createdAt
            }
        },
        welcomeMsgId
    };
    data.groups[String(id)] = group;
    saveGroups(data);
    return group;
}
export function addMessage(groupId, msgObj) {
    const data = loadGroups();
    const group = data.groups[String(groupId)];
    if (!group) return null;
    const ts = Date.now();
    let key = String(ts);
    while (group.messages[key]) key = String(Number(key) + 1);
    group.messages[key] = { ...msgObj, timestamp: Number(key) };
    saveGroups(data);
    return { id: key, message: group.messages[key] };
}
export function editMessage(groupId, msgId, newText, uid) {
    const data = loadGroups();
    const group = data.groups[String(groupId)];
    if (!group) return { error: "Group Not Found" };
    const msg = group.messages[msgId];
    if (!msg) return { error: "Message Not Found" };
    if (msg.s !== uid) return { error: "You Can Only Edit Your Own Messages" };
    msg.t = newText;
    msg.edited = true;
    saveGroups(data);
    return { success: true, message: msg };
}
export function deleteMessage(groupId, msgId, uid, allowOwnerDelete = true) {
    const data = loadGroups();
    const group = data.groups[String(groupId)];
    if (!group) return { error: "Group Not Found" };
    const msg = group.messages[msgId];
    if (!msg) return { error: "Message Not Found" };
    if (msg.s !== uid && !(allowOwnerDelete && group.ownerUid === uid)) {
        return { error: "Not Allowed To Delete This Message" };
    }
    delete group.messages[msgId];
    saveGroups(data);
    return { success: true };
}
export function addMember(groupId, uid) {
    const data = loadGroups();
    const group = data.groups[String(groupId)];
    if (!group) return { error: "Group Not Found" };
    if (group.members.includes(uid)) return { error: "Already A Member" };
    if (group.members.length >= MAX_GROUP_MEMBERS) return { error: `Group Is Full (Max ${MAX_GROUP_MEMBERS} Members)` };
    group.members.push(uid);
    if (!group.lastRead) group.lastRead = {};
    group.lastRead[uid] = Date.now();
    saveGroups(data);
    return { success: true, group };
}
export function markGroupRead(groupId, uid) {
    const data = loadGroups();
    const group = data.groups[String(groupId)];
    if (!group) return { error: "Group Not Found" };
    if (!isMember(group, uid)) return { error: "You Are Not A Member Of This Group" };
    if (!group.lastRead) group.lastRead = {};
    group.lastRead[uid] = Date.now();
    saveGroups(data);
    return { success: true };
}
export function toggleReaction(groupId, msgId, uid, emoji) {
    const data = loadGroups();
    const group = data.groups[String(groupId)];
    if (!group) return { error: "Group Not Found" };
    if (!isMember(group, uid)) return { error: "You Are Not A Member Of This Group" };
    const msg = group.messages[msgId];
    if (!msg) return { error: "Message Not Found" };
    if (typeof emoji !== "string" || !emoji || emoji.length > 8) return { error: "Invalid Emoji" };
    const reactions = msg.reactions ? { ...msg.reactions } : {};
    const emojiReactors = reactions[emoji] ? { ...reactions[emoji] } : {};
    const alreadyReacted = !!emojiReactors[uid];
    if (alreadyReacted) {
        delete emojiReactors[uid];
        if (Object.keys(emojiReactors).length === 0) {
            delete reactions[emoji];
        } else {
            reactions[emoji] = emojiReactors;
        }
    } else {
        if (!reactions[emoji] && Object.keys(reactions).length >= MAX_REACTIONS_PER_MSG) {
            return { error: `Max ${MAX_REACTIONS_PER_MSG} Different Reactions Per Message` };
        }
        let userReactionCount = 0;
        for (const e of Object.keys(reactions)) {
            if (reactions[e]?.[uid]) userReactionCount++;
        }
        if (userReactionCount >= MAX_REACTIONS_PER_USER_MSG) {
            return { error: `Max ${MAX_REACTIONS_PER_USER_MSG} Reactions Per User Per Message` };
        }
        reactions[emoji] = { ...emojiReactors, [uid]: true };
    }
    msg.reactions = reactions;
    saveGroups(data);
    return { success: true, reactions };
}
export function kickMember(groupId, requesterUid, targetUid) {
    const data = loadGroups();
    const group = data.groups[String(groupId)];
    if (!group) return { error: "Group Not Found" };
    if (group.ownerUid !== requesterUid) return { error: "Only The Owner Can Kick Members" };
    if (targetUid === group.ownerUid) return { error: "The Owner Cannot Be Kicked" };
    if (!group.members.includes(targetUid)) return { error: "User Is Not In This Group" };
    group.members = group.members.filter(m => m !== targetUid);
    saveGroups(data);
    return { success: true, group };
}
export function leaveGroup(groupId, uid) {
    const data = loadGroups();
    const group = data.groups[String(groupId)];
    if (!group) return { error: "Group Not Found" };
    if (!group.members.includes(uid)) return { error: "You Are Not In This Group" };
    if (group.ownerUid === uid) {
        return { error: "Owners Must Transfer Ownership Or Delete The Group Before Leaving" };
    }
    group.members = group.members.filter(m => m !== uid);
    saveGroups(data);
    return { success: true };
}
export function renameGroup(groupId, requesterUid, newName) {
    const data = loadGroups();
    const group = data.groups[String(groupId)];
    if (!group) return { error: "Group Not Found" };
    if (group.ownerUid !== requesterUid) return { error: "Only The Owner Can Rename The Group" };
    group.name = String(newName).slice(0, 60);
    saveGroups(data);
    return { success: true, group };
}
export function resetInvite(groupId, requesterUid, hostUrl) {
    const data = loadGroups();
    const group = data.groups[String(groupId)];
    if (!group) return { error: "Group Not Found" };
    if (group.ownerUid !== requesterUid) return { error: "Only The Owner Can Reset The Invite" };
    const newCode = generateInviteCode();
    group.inviteCode = newCode;
    group.inviteLink = `${hostUrl}/join/${newCode}`;
    if (group.welcomeMsgId && group.messages[group.welcomeMsgId]) {
        group.messages[group.welcomeMsgId].t = welcomeMessageText(group.name, newCode, hostUrl);
    }
    saveGroups(data);
    return { success: true, group };
}
export function transferOwnership(groupId, requesterUid, targetUid) {
    const data = loadGroups();
    const group = data.groups[String(groupId)];
    if (!group) return { error: "Group Not Found" };
    if (group.ownerUid !== requesterUid) return { error: "Only The Owner Can Transfer Ownership" };
    if (!group.members.includes(targetUid)) return { error: "Target User Is Not A Member Of This Group" };
    group.ownerUid = targetUid;
    saveGroups(data);
    return { success: true, group };
}
export function deleteGroup(groupId, requesterUid) {
    const data = loadGroups();
    const group = data.groups[String(groupId)];
    if (!group) return { error: "Group Not Found" };
    if (group.ownerUid !== requesterUid) return { error: "Only The Owner Can Delete The Group" };
    delete data.groups[String(groupId)];
    saveGroups(data);
    return { success: true };
}
export function getAllGroups() {
    const data = loadGroups();
    return Object.values(data.groups).map(g => stripMessagesForList(g));
}