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
        sendTemplatedEmail,
        EMAIL_TEMPLATES = [],
        TEMPLATES_DIR,
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
    async function sendTestNotificationToUser(uid, displayName, customMessage) {
        try {
            const tokens = await _getPushTokensForUser(uid);
            if (!tokens.length) {
                console.log(`${displayName} (${uid}) Has No Notifications Enabled. Skipped.`);
                return { uid, sent: 0, failed: 0, skipped: true };
            }
            const title = customMessage?.title || "Test Notification";
            const body = customMessage?.body || `Hey ${displayName}, This Is A Test Notification Sent From The Server Terminal.`;
            const response = await admin.messaging().sendEachForMulticast({
                tokens,
                data: {
                    type: "test",
                    title,
                    body,
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
        console.log("Enter A Custom Title (Leave Blank For Default: \"Test Notification\")");
        rl.question("Title> ", (titleInput) => {
            const title = titleInput.trim();
            console.log("Enter A Custom Message Body (Leave Blank For Default Message)");
            rl.question("Message> ", (bodyInput) => {
                const body = bodyInput.trim();
                const customMessage = (title || body) ? { title: title || undefined, body: body || undefined } : null;
                console.log("\nUsers To Select From:");
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
                            await sendTestNotificationToUser(u.uid, u.displayName, customMessage);
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
                    await sendTestNotificationToUser(target.uid, target.displayName, customMessage);
                    mainMenu();
                });
            });
        });
    }
    function listEmailTemplateNames() {
        try {
            return fs.readdirSync(TEMPLATES_DIR)
                .filter((f) => f.toLowerCase().endsWith(".html"))
                .map((f) => f.slice(0, -5))
                .sort();
        } catch {
            return [];
        }
    }
    function getAllUsersForEmail() {
        const users = getDataCache()?.users || {};
        return Object.keys(users).map((uid) => {
            const profile = users[uid]?.profile || {};
            const settings = users[uid]?.settings || {};
            return { uid, displayName: profile.displayName || "Unknown User", email: settings.userEmail || profile.userEmail || "" };
        });
    }
    function buildTestVars(templateName, user) {
        const html = fs.readFileSync(path.join(TEMPLATES_DIR, `${templateName}.html`), "utf8");
        const keys = [...new Set([...html.matchAll(/\{\{\s*([A-Za-z0-9_]+)\s*\}\}/g)].map((m) => m[1]))];
        const defaults = {
            DISPLAYNAME: user.displayName,
            EMAIL: user.email,
            EMAIL1: user.email,
            EMAIL2: "new-email@example.com",
            UID: user.uid || "TEST_UID",
            TIER: "T3",
            EXPIRE: "3 days, 4 hours",
            LINK: "https://www.infinitecampus.xyz/InfiniteAccounts.html",
            CODE: "123456",
            OOBCODE: "TEST_OOB_CODE",
            ACTION: "verifyEmail",
        };
        const vars = {};
        for (const k of keys) vars[k] = defaults[k] ?? `TEST_${k}`;
        return vars;
    }
    async function sendTestEmailTo(templateName, user) {
        let email = user.email;
        if (!email && user.uid) {
            try {
                email = (await admin.auth().getUser(user.uid)).email || "";
            } catch {}
        }
        if (!email) {
            console.log(`${user.displayName} (${user.uid}) Has No Email On File. Skipped.`);
            return;
        }
        const meta = EMAIL_TEMPLATES.find((t) => t.id === templateName);
        const subject = `[TEST] ${meta?.defaultSubject || templateName}`;
        try {
            const vars = buildTestVars(templateName, { ...user, email });
            await sendTemplatedEmail(templateName, email, subject, vars);
            console.log(`Sent "${templateName}" To ${user.displayName} <${email}>`);
        } catch (err) {
            console.error(`Failed To Send To ${email}:`, err.message);
        }
    }
    function sendTestEmailPrompt() {
        if (!sendTemplatedEmail || !TEMPLATES_DIR) {
            console.log("Email Sending Is Not Available In This Build.");
            return mainMenu();
        }
        const templates = listEmailTemplateNames();
        if (!templates.length) {
            console.log(`No Email Templates Found In ${TEMPLATES_DIR}`);
            return mainMenu();
        }
        console.log("\nSend A Test Email");
        console.log("Templates:");
        templates.forEach((t, i) => console.log(`${i + 1}: ${t}`));
        rl.question("Template (Number Or Name)> ", (tInput) => {
            const tTrim = tInput.trim();
            const tNum = parseInt(tTrim, 10);
            const templateName = (!isNaN(tNum) && templates[tNum - 1]) || templates.find((t) => t.toLowerCase() === tTrim.toLowerCase());
            if (!templateName) {
                console.log("Template Not Found.");
                return mainMenu();
            }
            const users = getAllUsersForEmail();
            console.log("\nUsers To Select From:");
            users.forEach((u, i) => console.log(`${i + 1}: ${u.displayName} (${u.uid})`));
            console.log("To Select A User, Enter Their Number, Displayname, Or Uid");
            console.log("To Send To Any Address, Type The Email Address Directly");
            rl.question("Recipient> ", async (input) => {
                const trimmed = input.trim();
                if (!trimmed) {
                    console.log("No Selection Entered.");
                    return mainMenu();
                }
                if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) {
                    const match = users.find((u) => u.email.toLowerCase() === trimmed.toLowerCase());
                    await sendTestEmailTo(templateName, match || { uid: "", displayName: "Test User", email: trimmed });
                    return mainMenu();
                }
                const asNum = parseInt(trimmed, 10);
                const target = (!isNaN(asNum) && users[asNum - 1]) ||
                    users.find((u) => u.uid === trimmed || u.displayName.toLowerCase() === trimmed.toLowerCase());
                if (!target) {
                    console.log("User Not Found.");
                    return mainMenu();
                }
                await sendTestEmailTo(templateName, target);
                mainMenu();
            });
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
        console.log("6  Send Test Email");
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
                case "6":
                    sendTestEmailPrompt();
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