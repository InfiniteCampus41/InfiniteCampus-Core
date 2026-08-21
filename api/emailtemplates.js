import fs from "fs";
import path from "path";
import { DATA_ROOT } from "./channelsstore.js";
const TEMPLATES_DIR = path.join(DATA_ROOT, "templates");
/**
 * @param {string} templateName
 * @param {Object} vars
 * @returns {string}
 */
export function renderTemplate(templateName, vars = {}) {
    const filePath = path.join(TEMPLATES_DIR, `${templateName}.html`);
    if (!fs.existsSync(filePath)) {
        throw new Error(`Email Template Not Found: ${templateName}`);
    }
    let html = fs.readFileSync(filePath, "utf8");
    for (const [key, value] of Object.entries(vars)) {
        const token = `{{${key}}}`;
        html = html.split(token).join(value ?? "");
    }
    return html;
}
/**
 * @param {number} ms
 * @returns {string}
 */
export function formatExpire(ms) {
    if (!ms || ms <= 0) return "Expired";
    const totalSec = Math.floor(ms / 1000);
    const days = Math.floor(totalSec / 86400);
    const hours = Math.floor((totalSec % 86400) / 3600);
    const minutes = Math.floor((totalSec % 3600) / 60);
    if (days > 0) return `${days} day${days !== 1 ? "s" : ""}${hours > 0 ? `, ${hours} hour${hours !== 1 ? "s" : ""}` : ""}`;
    if (hours > 0) return `${hours} hour${hours !== 1 ? "s" : ""}${minutes > 0 ? `, ${minutes} minute${minutes !== 1 ? "s" : ""}` : ""}`;
    return `${minutes} minute${minutes !== 1 ? "s" : ""}`;
}
/**
 * @param {Object} profile
 * @returns {string}
 */
export function getPremiumTierLabel(profile) {
    if (profile?.premium3) return "T3";
    if (profile?.premium2) return "T2";
    if (profile?.premium1) return "T1";
    return "Premium";
}