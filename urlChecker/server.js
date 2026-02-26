const https = require("https");
const http = require("http");
const fetch = require("node-fetch");
const readline = require("readline");
const fs = require("fs");
const path = require("path");
const URL_FILE = path.join(__dirname, "urls.json");
const WEBHOOK_URL = "REDACTED";
const WEBHOOKS = {
    1: "REDACTED",
    2: "REDACTED",
    3: null
};

const colors = {
    reset: "\x1b[0m",
    red: "\x1b[31m",
    green: "\x1b[32m",
    yellow: "\x1b[33m",
    cyan: "\x1b[36m",
    bold: "\x1b[1m"
};
const CHECK_INTERVAL_MS = 5000;
let webhookDelaySeconds = 300;
let webhookDelayChecks = Math.floor(webhookDelaySeconds * 1000 / CHECK_INTERVAL_MS);
const BOX_WIDTH = 38;
const BOXES_PER_ROW = 3;
const ROW_HEIGHT = 4;
const MIN_BOX_WIDTH = 38;
const GAP = 3;
let URLS = [];
function loadURLs() {
    if (!fs.existsSync(URL_FILE)) {
        fs.writeFileSync(URL_FILE, JSON.stringify([], null, 2));
    }
    const raw = JSON.parse(fs.readFileSync(URL_FILE, "utf8"));
    URLS = raw.map((u, i) => {
        if (typeof u === "string") {
            return {
                url: u,
                order: i,
                services: [],
                webhooks: [1]
            };
        }
        return {
            url: u.url,
            order: u.order ?? i,
            services: u.services ?? [],
            webhooks: u.webhooks ?? [1]
        };
    });
    sortURLs();
}
function saveURLs() {
    fs.writeFileSync(URL_FILE, JSON.stringify(URLS, null, 2));
}
function sortURLs() {
    URLS.sort((a, b) => a.order - b.order);
}
function renderBox({ url }, index, result) {
    let statusColor = colors.green;
    if (!result.up) statusColor = colors.red;
    else if (result.latency > 500) statusColor = colors.yellow;
    return [
        `${statusColor}╔${"═".repeat(BOX_WIDTH - 2)}╗${colors.reset}`,
        `${statusColor}║${colors.reset} ${index + 1}. ${result.up ? "UP" : "DN"} ${url.slice(0, BOX_WIDTH - 10).padEnd(BOX_WIDTH - 10)}${statusColor}║${colors.reset}`,
        `${statusColor}║${colors.reset} ${result.latency}ms | ${result.status}`.padEnd(BOX_WIDTH - 1) + `${statusColor}║${colors.reset}`,
        `${statusColor}╚${"═".repeat(BOX_WIDTH - 2)}╝${colors.reset}`
    ];
}
let previous = {};
let downCount = {};
let startRow = 0;
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});
rl._writeToOutput = str => process.stdout.write(str);
console.clear();
loadURLs();
console.log(colors.cyan + colors.bold + "╔══════════════════════════════════════════════╗");
console.log("║                 URL MONITOR                  ║");
console.log("╚══════════════════════════════════════════════╝" + colors.reset);
console.log(colors.green + "Monitoring Active..." + colors.reset);
console.log(
  colors.cyan + "Commands: " + colors.reset +
  "a = Add URL, e = Edit Services, h = Set Webhooks, m = Move URL, r = Remove URL, s = View Services, w = Webhook Delay, q = Quit\n"
);
console.log(colors.bold + "Current URLs:\n" + colors.reset);
for (let i = 0; i < URLS.length; i++) {
    console.log(" ".repeat(80));
    console.log(" ".repeat(80));
    console.log(" ".repeat(80));
}
rl.prompt();
startRow = 7;
async function sendWebhookAlert(item, latency, status) {
    const services =
        item.services.length ? item.services.join(", ") : "None Provided";
    for (const id of item.webhooks) {
        const hook = WEBHOOKS[id];
        if (!hook) continue;
        try {
            await fetch(hook, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    username: "URL Monitor",
                    content:
`**OUTAGE DETECTED**

**${item.url}** Is **DOWN**
Latency: ${latency}ms
Status: ${status}

**Affected Services**
${services}`
                })
            });
        } catch (err) {
            console.log(colors.red + `Webhook ${id} Failed: ${err}` + colors.reset);
        }
    }
    console.log(
        colors.red +
        `\n[!] ${item.url} DOWN → Webhooks: ${item.webhooks.join(", ")}` +
        colors.reset
    );
}
function checkURL(url) {
    return new Promise(resolve => {
        const start = Date.now();
        fetch(url, { method: "GET" })
            .then(async res => {
                const latency = Date.now() - start;
                let up = res.ok;
                let text = "";
                try { text = await res.text(); } catch {}
                const blockReasons = ["removed by admin", "domain spelled right", "not found anywhere"];
                if (blockReasons.some(r => text.toLowerCase().includes(r))) {
                    up = false;
                }
                resolve({ up, latency, status: res.status });
            })
            .catch(() =>
                resolve({ up: false, latency: Date.now() - start, status: "DOWN" })
            );
    });
}
async function sendRecoveryAlert(item, latency) {
    for (const id of item.webhooks) {
        const hook = WEBHOOKS[id];
        if (!hook) continue;
        await fetch(hook, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                username: "URL Monitor",
                content:
`**RECOVERY DETECTED**

**${item.url}** Is Back **UP**
Latency: ${latency}ms`
            })
        });
    }
}
async function updateDisplay() {
    sortURLs();
    let rowCursor = startRow;
    const TERM_WIDTH = process.stdout.columns || 120;
    const ROW_HEIGHT = 4;
    function buildBox(item, index, result, boxWidth) {
        let statusColor = colors.green;
        if (!result.up) statusColor = colors.red;
        else if (result.latency > 500) statusColor = colors.yellow;
        const INNER = boxWidth - 2;
        const statusText = result.up ? "UP" : "DN";
        const prefix = `${index + 1}. ${statusText} `;
        const urlSpace = INNER - prefix.length;
        const urlText = item.url.padEnd(urlSpace).slice(0, urlSpace);
        const line1 = prefix + urlText;
        const latencyLine = `${result.latency}ms | ${result.status}`.padEnd(INNER);
        return [
            `${statusColor}╔${"═".repeat(INNER)}╗${colors.reset}`,
            `${statusColor}║${colors.reset}${line1}${statusColor}║${colors.reset}`,
            `${statusColor}║${colors.reset}${latencyLine}${statusColor}║${colors.reset}`,
            `${statusColor}╚${"═".repeat(INNER)}╝${colors.reset}`
        ];
    }
    let i = 0;
    while (i < URLS.length) {
        let row = [];
        let usedWidth = 0;
        while (i < URLS.length) {
            const needed =
                Math.max(
                    MIN_BOX_WIDTH,
                    URLS[i].url.length + 8
                );
            const projected =
                usedWidth +
                (row.length ? GAP : 0) +
                needed;
            if (projected > TERM_WIDTH) break;
            row.push({ item: URLS[i], needed });
            usedWidth = projected;
            i++;
        }
        const rowBoxWidth = Math.min(
            TERM_WIDTH,
            Math.max(...row.map(r => r.needed))
        );
        const rendered = [];
        for (let j = 0; j < row.length; j++) {
            const { item } = row[j];
            const result = await checkURL(item.url);
            if (!downCount[item.url]) downCount[item.url] = 0;
            if (!result.up) {
                downCount[item.url]++;
            } else {
                if (downCount[item.url] >= 12) {
                    sendRecoveryAlert(item, result.latency);
                }
                downCount[item.url] = 0;
            }
            if (downCount[item.url] === webhookDelayChecks) {
                sendWebhookAlert(item, result.latency, result.status);
	    }
            rendered.push(
                buildBox(item, i - row.length + j, result, rowBoxWidth)
            );
        }
        for (let line = 0; line < ROW_HEIGHT; line++) {
            const text = rendered.map(b => b[line]).join(" ".repeat(GAP));
            process.stdout.write(`\x1b[${rowCursor}H${text}`);
            rowCursor++;
        }
        const sepWidth =
            row.length * rowBoxWidth + (row.length - 1) * GAP;
            process.stdout.write(`\x1b[${rowCursor++}H${"─".repeat(sepWidth)}`);
            process.stdout.write(`\x1b[${rowCursor++}H${"─".repeat(sepWidth)}`);
    }
    process.stdout.write(`\x1b[${rowCursor}H`);
    rl.prompt(true);
}
setInterval(async () => {
    for (let url of Object.keys(downCount)) {
        const result = await checkURL(url);
        if (result.up) downCount[url] = 0;
    }
}, 15000);
setInterval(updateDisplay, 5000);
rl.on("line", input => {
    input = input.trim().toLowerCase();
    if (input === "q") {
        console.log("\nExiting...");
        console.clear();
        process.exit(0);
    }
    if (input === "a") {
        rl.question("Enter URL: ", url => {
            rl.question("Services (Separated By Comma): ", svc => {
                const services = svc
                    .split(",")
                    .map(s => s.trim())
                    .filter(Boolean);
                URLS.push({
                    url,
                    order: URLS.length,
                    services
                });
                saveURLs();
                console.log(colors.green + "URL + Services Added!" + colors.reset);
                rl.prompt();
            });
        });
        return;
    }
    if (input === "e") {
        rl.question("URL number: ", n => {
            const idx = parseInt(n) - 1;
            if (!URLS[idx]) {
                console.log(colors.red + "Invalid URL." + colors.reset);
                return rl.prompt();
            }
            rl.question(
                "New Services (Separated By Comma): ",
                svc => {
                    URLS[idx].services = svc
                        .split(",")
                        .map(s => s.trim())
                        .filter(Boolean);
                    saveURLs();
                    console.log(colors.green + "Services Updated." + colors.reset);
                    rl.prompt();
                }
            );
        });
        return;
    }
    if (input === "h") {
        rl.question("URL Number: ", n => {
            const idx = parseInt(n) - 1;
            if (!URLS[idx]) {
                console.log(colors.red + "Invalid URL." + colors.reset);
                return rl.prompt();
            }
            rl.question(
                "Webhook Numbers (1-3, Separated By Comma): ",
                answer => {
                    const hooks = answer
                        .split(",")
                        .map(n => parseInt(n.trim()))
                        .filter(n => n >= 1 && n <= 3 && WEBHOOKS[n]);
                    if (!hooks.length) {
                        console.log(colors.red + "No Valid Webhooks Selected." + colors.reset);
                    } else {
                        URLS[idx].webhooks = hooks;
                        saveURLs();
                        console.log(
                            colors.green +
                            `Webhooks Updated → ${hooks.join(", ")}` +
                            colors.reset
                        );
                    }
                    rl.prompt();
                }
            );
        });
        return;
    }
    if (input === "m") {
        rl.question("Move Which Number? ", from => {
            rl.question("Move to position? ", to => {
                from = parseInt(from) - 1;
                to = parseInt(to) - 1;
                if (
                    from < 0 || from >= URLS.length ||
                    to < 0 || to >= URLS.length
                ) {
                    console.log(colors.red + "Invalid Positions." + colors.reset);
                    rl.prompt();
                    return;
                }
                const item = URLS.splice(from, 1)[0];
                URLS.splice(to, 0, item);
                URLS.forEach((u, i) => (u.order = i));
                saveURLs();
                console.log(colors.green + "Order Updated!" + colors.reset);
                rl.prompt();
            });
        });
        return;
    }
    if (input === "r") {
        rl.question("Enter Number To Remove: ", num => {
            num = parseInt(num);
            if (!num || num < 1 || num > URLS.length) {
                console.log(colors.red + "Invalid Number." + colors.reset);
                rl.prompt();
                return;
            }
            const url = URLS[num - 1];
            rl.question(`Remove "${url}"? (y/n): `, confirm => {
                if (confirm.toLowerCase() === "y") {
                    URLS.splice(num - 1, 1);
                    delete downCount[url];
                    saveURLs();
                    console.log(colors.red + "URL Removed!" + colors.reset);
                }
                rl.prompt();
            });
        });
        return;
    }
    if (input === "s") {
        rl.question("URL Number: ", n => {
            const idx = parseInt(n) - 1;
            if (!URLS[idx]) {
                console.log(colors.red + "Invalid URL." + colors.reset);
            } else {
                const services =
                    URLS[idx].services.length
                        ? URLS[idx].services.join(", ")
                        : "No Services Defined";
                console.log(
                    colors.cyan +
                    `\nServices For ${URLS[idx].url}:\n` +
                    colors.bold +
                    services +
                    colors.reset
                );
            }
            rl.prompt();
        });
        return;
    }
    if (input === "w") {
        rl.question("Webhook Delay In Seconds: ", value => {
            const seconds = parseInt(value);
            if (isNaN(seconds) || seconds <= 0) {
                console.log(colors.red + "Invalid Time." + colors.reset);
                rl.prompt();
                return;
            }
            webhookDelaySeconds = seconds;
            webhookDelayChecks = Math.floor((seconds * 1000) / CHECK_INTERVAL_MS);
            console.log(
                colors.cyan +
                `Webhook Will Trigger After ${webhookDelaySeconds}s (${webhookDelayChecks} Checks)` +
                colors.reset
            );
            rl.prompt();
        });
        return;
    }
    rl.prompt();
});