import readline from "readline";
import fs from "fs";
import path from "path";
let _listFilesInterval = null;
export function initDevCli(ctx) {
    const {
        rl,
        admin,
        getDataCache,
        readDataPath,
        _getPushTokensForUser,
        logEvent,
        pruneInvalidTokens,
        UPLOADS_DIR,
        AUTO_DELETE_MS,
        formatBytes,
        getUploadLogs,
        getActiveLinks,
        getRateLimitLogs,
        getLockdown,
        setLockdown,
    } = ctx;
    function renderScreen(lines) {
        const currentInput = rl.line || "";
        const prompt = rl.getPrompt() || "> ";
        readline.cursorTo(process.stdout, 0, 0);
        readline.clearScreenDown(process.stdout);
        for (const ln of lines) process.stdout.write(ln + "\n");
        process.stdout.write(prompt + currentInput);
        readline.cursorTo(process.stdout, prompt.length + currentInput.length);
    }
    function listFilesLive() {
        if (_listFilesInterval) clearInterval(_listFilesInterval);
        const renderList = () => {
            const files = fs.readdirSync(UPLOADS_DIR).filter((f) => fs.statSync(path.join(UPLOADS_DIR, f)).isFile());
            const uploadLogs = getUploadLogs();
            const activeLinks = getActiveLinks();
            const rateLimitLogs = getRateLimitLogs();
            const lines = [];
            lines.push(`LIVE FILE LIST (${files.length} Files)`);
            lines.push("───────────────────────────────────────────────────────────────────────");
            if (uploadLogs.length > 0) {
                lines.push("Recent Upload Logs:");
                const lastUploadLogs = uploadLogs.slice(-10);
                for (const l of lastUploadLogs) lines.push("  " + l.message);
                lines.push("───────────────────────────────────────────────────────────────────────");
            }
            if (activeLinks.length > 0) {
                lines.push("Download Links:");
                const lastLinks = activeLinks.slice(-10);
                for (const l of lastLinks) lines.push("  " + l.url);
                lines.push("───────────────────────────────────────────────────────────────────────");
            }
            if (rateLimitLogs.length > 0) {
                lines.push("Rate-Limit / Queue Logs:");
                const lastRateLogs = rateLimitLogs.slice(-10);
                for (const l of lastRateLogs) lines.push("  " + l.message);
                lines.push("───────────────────────────────────────────────────────────────────────");
            }
            if (files.length === 0) {
                lines.push("No Files Uploaded.");
            } else {
                lines.push(" # | File Name                     | Size     | Age(s) | Deletes In(s)");
                lines.push("───┼───────────────────────────────┼──────────┼────────┼──────────────");
                files.forEach((file, i) => {
                    let stats;
                    try {
                        stats = fs.statSync(path.join(UPLOADS_DIR, file));
                    } catch {
                        return null;
                    }
                    const age = Math.floor((Date.now() - stats.birthtimeMs) / 1000);
                    const remain = Math.max(0, Math.floor((AUTO_DELETE_MS - (Date.now() - stats.birthtimeMs)) / 1000));
                    const size = formatBytes(stats.size).padEnd(8);
                    const name = file.length > 30 ? file.slice(0, 27) + ".." : file.padEnd(30);
                    lines.push(`${String(i + 1).padEnd(2)} | ${name} | ${size} | ${String(age).padEnd(6)} | ${remain}`);
                });
            }
            lines.push("───────────────────────────────────────────────────────────────────────");
            lines.push("Type A File Number To Get A Download Link,");
            lines.push("Type DELETE # To Delete A File,");
            lines.push("Type MENU To Return To The Main Menu.");
            renderScreen(lines);
        };
        _listFilesInterval = setInterval(renderList, 1000);
        renderList();
    }

    function deleteFilePrompt() {
        const files = fs.readdirSync(UPLOADS_DIR).filter((f) => fs.statSync(path.join(UPLOADS_DIR, f)).isFile());
        if (files.length === 0) return console.log("No Files To Delete."), mainMenu();
        console.log("\nAvailable Files:");
        files.forEach((f, i) => console.log(`${i + 1}. ${f}`));
        rl.question("Enter Number To Delete: ", (num) => {
            const idx = parseInt(num) - 1;
            if (!isNaN(idx) && files[idx]) {
                fs.unlinkSync(path.join(UPLOADS_DIR, files[idx]));
                console.log(`Deleted ${files[idx]}`);
            }
            mainMenu();
        });
    }
    function toggleLockdown() {
        setLockdown(!getLockdown());
        console.log(getLockdown() ? "Uploads Locked." : "Uploads Unlocked.");
        mainMenu();
    }
    function getNotifiableUsers() {
        const data = getDataCache();
        const notifications = data?.notifications || {};
        const uids = Object.keys(notifications);
        return uids.map((uid) => {
            const profile = readDataPath(`users/${uid}/profile`);
            return { uid, displayName: profile?.displayName || "Unknown User" };
        });
    }
    async function sendTestNotificationToUser(uid, displayName) {
        try {
            const tokens = await _getPushTokensForUser(uid);
            if (!tokens.length) {
                console.log(`${displayName} (${uid}) Has No Notifications Enabled. Skipped.`);
                return { uid, sent: 0, failed: 0, skipped: true };
            }
            const response = await admin.messaging().sendEachForMulticast({
                tokens,
                data: {
                    type: "test",
                    title: "Test Notification",
                    body: `Hey ${displayName}, This Is A Test Notification Sent From The Server Terminal.`,
                    url: "/InfiniteChatters.html?chat=true"
                }
            });
            pruneInvalidTokens(tokens, response, uid);
            logEvent("notifications", {
                id: `test_${uid}_${Date.now()}`,
                data: { type: "test", to: uid, from: "terminal" }
            });
            console.log(`${displayName} (${uid}) — Sent: ${response.successCount}  Failed: ${response.failureCount}`);
            return { uid, sent: response.successCount, failed: response.failureCount, skipped: false };
        } catch (err) {
            console.error(`${displayName} (${uid}) — Error:`, err.message);
            return { uid, sent: 0, failed: 0, skipped: false, error: err.message };
        }
    }
    function sendTestNotificationPrompt() {
        const users = getNotifiableUsers();
        if (!users.length) {
            console.log("No Users Found Under Notifications Data.");
            return mainMenu();
        }
        console.log("\nSend A Test Notification");
        console.log("Users To Select From:");
        users.forEach((u, i) => console.log(`${i + 1}: ${u.displayName} (${u.uid})`));
        console.log("To Select A User, Enter Their Number, Displayname, Or Uid");
        console.log("To Select All Users, Type ALL");
        rl.question("> ", async (input) => {
            const trimmed = input.trim();
            if (!trimmed) {
                console.log("No Selection Entered.");
                return mainMenu();
            }
            if (trimmed.toUpperCase() === "ALL") {
                for (const u of users) {
                    await sendTestNotificationToUser(u.uid, u.displayName);
                }
                return mainMenu();
            }
            let target = null;
            const asNum = parseInt(trimmed, 10);
            if (!isNaN(asNum) && users[asNum - 1]) {
                target = users[asNum - 1];
            } else {
                target = users.find(
                    (u) => u.uid === trimmed || u.displayName.toLowerCase() === trimmed.toLowerCase()
                );
            }
            if (!target) {
                console.log("User Not Found.");
                return mainMenu();
            }
            await sendTestNotificationToUser(target.uid, target.displayName);
            mainMenu();
        });
    }
    function mainMenu() {
        if (_listFilesInterval) {
            clearInterval(_listFilesInterval);
            _listFilesInterval = null;
        }
        console.log("\n FILE SERVER MENU");
        console.log("1  Files");
        console.log("2  Delete A File");
        console.log("3  Lockdown (Currently: " + (getLockdown() ? "ON" : "OFF") + ")");
        console.log("4  Exit");
        console.log("5  Send Test Notification");
        rl.question("Choose An Option: ", (a) => {
            switch (a.trim()) {
                case "1":
                    listFilesLive();
                    break;
                case "2":
                    deleteFilePrompt();
                    break;
                case "3":
                    toggleLockdown();
                    break;
                case "4":
                    console.log("Exiting...");
                    rl.close();
                    console.clear();
                    process.exit(0);
                case "5":
                    sendTestNotificationPrompt();
                    break;
                default:
                    console.log("Invalid Choice");
                    mainMenu();
            }
        });
    }
    rl.setPrompt("> ");
    mainMenu();
}