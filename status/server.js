const express = require("express");
const admin = require("firebase-admin");
const axios = require("axios");
const app = express();
admin.initializeApp({
    credential: admin.credential.cert(require("./admin.json")),
    databaseURL: "https://status-ba6c4-default-rtdb.firebaseio.com"
});
const db = admin.database();
const sites = {
    infinitecampusxyz: "https://infinitecampus.xyz",
    instructurespace: "https://instructure.space",
    apiinfinitecampusxyz: "https://api.infinitecampus.xyz",
    backupinfinitecampusxyz: "https://backup.infinitecampus.xyz",
    devsinfinitecampusxyz: "https://devs.infinitecampus.xyz",
    playinfinitecampusxyz: "https://play.infinitecampus.xyz",
    docsinfinitecampusxyz: "https://docs.infinitecampus.xyz"
};
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
            headers: { "User-Agent": "StatusMonitor" }
        });
        return res.status >= 200 && res.status < 400;
    } catch (err) {
        console.log("NETWORK ERROR:", url, err.code || err.message);
        return false;
    }
}
let running = false;
async function checkSites() {
    if (running) return;
    running = true;
    const now = new Date();
    const key = hourKeyUTC(now);
    const cutoff = Date.now() - 24 * 60 * 60 * 1000;
    console.log("Checking Sites @", now.toISOString());
    for (const [id, url] of Object.entries(sites)) {
        try {
            const isUp = await safeFetch(url);
            const ref = db.ref(`status/${id}/${key}`);
            const snap = await ref.get();
            let downMinutes = snap.exists()
                ? snap.val().downMinutes || 0
                : 0;
            if (!isUp) downMinutes += 5;
            const hourUp = downMinutes < 10;
            await ref.set({downMinutes, up: hourUp});
            console.log( id, hourUp ? "UP" : "DOWN", `(${downMinutes} Min)` );
            const all = await db.ref(`status/${id}`).get();
            all.forEach(child => {
                const [year, month, day, hour] = child.key.split("-").map(Number);
                const entryTime = Date.UTC(year, month - 1, day, hour);
                if (entryTime < cutoff) {
                    console.log("Deleting Old Hour:", id, child.key);
                    child.ref.remove();
                }
            });
        } catch (err) {
            console.error("Error Checking", id, err.message);
        }
    }
    running = false;
}
app.get("/", (req, res) => {
    res.send("Status Monitor Running");
});
app.listen(3000, async () => {
    console.log("Server Started On Port 3000");
    await checkSites();
    setInterval(checkSites, 5 * 60 * 1000);
});