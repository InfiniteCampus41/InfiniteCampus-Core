const express = require("express");
const admin = require("firebase-admin");
const axios = require("axios");
const app = express();
admin.initializeApp({
    credential: admin.credential.cert(require("./admin.json")),
    databaseURL: "https://status-ba6c4-default-rtdb.firebaseio.com"
});
const db = admin.database();
let running = false;
const CHECK_INTERVAL_MS = 5 * 60 * 1000;
const RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
async function checkSites() {
    if (running) return;
    running = true;
    const now = new Date();
    const key = hourKeyUTC(now);
    const cutoff = Date.now() - RETENTION_MS;
    console.log("Checking Sites @", now.toISOString());
    const sitesSnap = await db.ref("sites").get();
    if (!sitesSnap.exists()) {
        console.log("No Sites Configured");
        running = false;
        return;
    }
    const sitesRoot = sitesSnap.val();
    for (const num of Object.keys(sitesRoot)) {
        const site = sitesRoot[num];
        if (!site.url) continue;
        const url = site.url;
        try {
            const isUp = await safeFetch(url);
            const statusRef = db.ref(`sites/${num}/status/${key}`);
            const snap = await statusRef.get();
            let downMinutes = snap.exists() ? snap.val().downMinutes || 0 : 0;
            if (!isUp) downMinutes += 5;
            const hourUp = downMinutes < 10;
            await statusRef.set({ downMinutes, up: hourUp });
            console.log(`Site ${num} (${site.name}) is ${hourUp ? "UP" : "DOWN"} (${downMinutes} min)`);
            const allStatusSnap = await db.ref(`sites/${num}/status`).get();
            allStatusSnap.forEach(child => {
                const [year, month, day, hour] = child.key.split("-").map(Number);
                const entryTime = Date.UTC(year, month - 1, day, hour);
                if (entryTime < cutoff) {
                    console.log("Deleting Old Hour:", num, child.key);
                    child.ref.remove();
                }
            });
            const maintRef = db.ref(`sites/${num}/maint`);
            const maintSnap = await maintRef.get();
            if (maintSnap.exists()) {
                const maint = maintSnap.val();
                if (maint.end && maint.end * 1000 < cutoff) {
                    console.log("Cleaning Expired Maintenance (past retention):", num);
                    maintRef.remove();
                }
            }
        } catch (err) {
            console.error(`Error checking site ${num} (${site.name})`, err.message);
        }
    }
    running = false;
}
function hourKeyUTC(date = new Date()) {
    return (
        date.getUTCFullYear() +
        "-" +
        String(date.getUTCMonth() + 1).padStart(2, "0") +
        "-" +
        String(date.getUTCDate()).padStart(2, "0") +
        "-" +
        String(date.getUTCHours()).padStart(2, "0")
    );
}
async function safeFetch(url) {
    try {
        const res = await axios.get(url, {
            timeout: 7000,
            headers: { "User-Agent": "StatusMonitor" },
            validateStatus: () => true
        });
        if (res.status >= 400) return false;
        const html = typeof res.data === "string" ? res.data.toLowerCase() : "";
        if (
            html.includes("there isn't a github pages site here") ||
            html.includes("github pages site not found") ||
            (html.includes("404") && html.includes("github"))
        ) return false;
        return true;
    } catch (err) {
        console.log("NETWORK ERROR:", url, err.code || err.message);
        return false;
    }
}
app.get("/", (req, res) => {
    res.send("Status Monitor Running");
});
function msUntilNextAlignedCheck() {
    const now = Date.now();
    return CHECK_INTERVAL_MS - (now % CHECK_INTERVAL_MS);
}
app.listen(3000, async () => {
    console.log("Server Started On Port 3000");
    await checkSites();
    setTimeout(() => {
        checkSites();
        setInterval(checkSites, CHECK_INTERVAL_MS);
    }, msUntilNextAlignedCheck());
});