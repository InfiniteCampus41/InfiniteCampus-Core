const express = require("express");
const { initializeApp, cert } = require("firebase-admin/app");
const { getDatabase } = require("firebase-admin/database");
const axios = require("axios");
const { Client, GatewayIntentBits, REST, Routes, SlashCommandBuilder, MessageFlags, PermissionFlagsBits, EmbedBuilder, ModalBuilder, TextInputBuilder, TextInputStyle, ActionRowBuilder } = require("discord.js");
const { Jimp } = require("jimp");
const dotenv = require("dotenv");
const fs = require("fs");
dotenv.config();
const LOCK_FILE = "./bot.lock";
try {
    const pid = fs.readFileSync(LOCK_FILE, "utf8").trim();
    try { process.kill(Number(pid), 0); } catch { fs.unlinkSync(LOCK_FILE); }
    if (fs.existsSync(LOCK_FILE)) {
        console.error(`[Bot] Another instance is already running (PID ${pid}). Exiting.`);
        process.exit(1);
    }
} catch { /* no lock file yet */ }
fs.writeFileSync(LOCK_FILE, String(process.pid));
process.on("exit", () => { try { fs.unlinkSync(LOCK_FILE); } catch {} });
process.on("SIGINT",  () => process.exit(0));
process.on("SIGTERM", () => process.exit(0));
process.on("uncaughtException",  (err) => { console.error("[Bot] Uncaught exception:", err); process.exit(1); });
process.on("unhandledRejection", (err) => { console.error("[Bot] Unhandled rejection:", err); process.exit(1); });
const app = express();
const DB_URL = process.env.DB_URL;
const BOT_TOKEN = process.env.BOT_TOKEN;
const CL_ID = process.env.CL_ID;
const GU_ID = process.env.GU_ID;
const IC_CHANNEL = process.env.IC_CHANNEL;
const API_CHANNEL = process.env.API_CHANNEL;
const SPACE_CHANNEL = process.env.SPACE_CHANNEL;
const ALERT_ID = process.env.ALERT_ID;
const MOD_ID = process.env.MOD_ID;
const JOINLEAVE_ID = process.env.JOINLEAVE_ID;
const MEMBER_ID = process.env.MEMBER_ID;
const ANNOUNCE_ID = process.env.ANNOUNCE_ID;
const OG_ID = process.env.OG_ID;
const INV_LINK = process.env.INV_LINK;
const OWNER_UID = process.env.OWNER_UID;
const AD1_UID = process.env.AD1_UID;
const AD2_UID = process.env.AD2_UID;
const AD3_UID = process.env.AD3_UID;
const AD4_UID = process.env.AD4_UID;
const AD5_UID = process.env.AD5_UID;
const WARN1 = process.env.WARN1;
const WARN2 = process.env.WARN2;
const WARN3 = process.env.WARN3;
const WARN4 = process.env.WARN4;
const AD_PASS_1 = process.env.AD_PASS_1;
const AD_PASS_2 = process.env.AD_PASS_2;
const AD_PASS_3 = process.env.AD_PASS_3;
const DT_PING = process.env.DT_PING;
initializeApp({
    credential: cert(require("./admin.json")),
    databaseURL: DB_URL
});
const db = getDatabase();
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
const CHECK_INTERVAL = 30_000;
const FAILURE_THRESHOLD = 4;
const VARS_FILE = "./vars.json";
let vars = { sticky: {}, counting: {} };
if (fs.existsSync(VARS_FILE)) {
	vars = JSON.parse(fs.readFileSync(VARS_FILE));
}
if (!vars.sticky) vars.sticky = {};
if (!vars.counting) {
	vars.counting = {
		channel: null,
		num: 0,
		uid: null,
		enabled: false
	};
}
function saveVars() {
	fs.writeFileSync(VARS_FILE, JSON.stringify(vars, null, 2));
}
const GREEN = "🟢";
const RED = "🔴";
const MAX_RETRIES = 5;
const RETRY_DELAY = 5000;
const client = new Client({
    intents: [
		GatewayIntentBits.Guilds,
		GatewayIntentBits.GuildMessages,
		GatewayIntentBits.MessageContent,
		GatewayIntentBits.GuildMembers
	]
});
const sites = [
  	{
    	name: "InfiniteCampus",
    	label: "Infinitecampus.xyz",
    	url: "https://infinitecampus.xyz",
    	channelId: IC_CHANNEL,
    	services: "Website",
    	failures: 0,
    	isDown: false,
    	alertMessageId: null
  	},
  	{
    	name: "InfiniteCampus API",
    	label: "API Status",
    	url: "https://api.infinitecampus.xyz",
    	channelId: API_CHANNEL,
    	services: "Movie Streaming, Chat, File Upload, Games",
    	failures: 0,
    	isDown: false,
    	alertMessageId: null
  	},
  	{
    	name: "InfiniteCampus Second Link",
    	label: "Instructure.space",
    	url: "https://instructure.space",
    	channelId: SPACE_CHANNEL,
    	services: "Mirror Website Link",
    	failures: 0,
    	isDown: false,
    	alertMessageId: null
  	}
];
async function retry(fn, retries = MAX_RETRIES, delay = RETRY_DELAY) {
  	for (let i = 0; i < retries; i++) {
    	try {
      		return await fn();
    	} catch (err) {
      		if (
        		err.code === "EAI_AGAIN" ||
        		err.code === "ENOTFOUND" ||
        		err.code === "ECONNRESET"
      		) {
        		console.log(`Network Error (${err.code}). Retry ${i + 1}/${retries}...`);
        		await new Promise(r => setTimeout(r, delay));
      		} else {
        		throw err;
      		}
    	}
  	}
  	throw new Error("Max Retries Reached For Network Operation.");
}
const commandHandlers = {};
const recentlyBanned = new Set();
const recentlyKicked = new Set();
function addCommand(builder, handler) {
	const json = builder.toJSON();
	commandHandlers[json.name] = handler;
	return json;
}
async function checkSite(site) {
  	try {
    	return await retry(async () => {
      		const res = await fetch(site.url, { method: "HEAD", timeout: 10_000 });
      		return res.ok;
    	});
  	} catch {
    	return false;
  	}
}
async function updateChannelName(site, isUp) {
  	const channel = await client.channels.fetch(site.channelId).catch(() => null);
  	if (!channel) return;
  	const emoji = isUp ? GREEN : RED;
  	const newName = `${site.label}: ${emoji}`;
  	if (channel.name !== newName) {
    	await channel.setName(newName).catch(console.error);
  	}
}
async function sendAlert(message) {
  	const channel = await client.channels.fetch(ALERT_ID).catch(() => null);
  	if (!channel) return null;
  	return channel.send(message).catch(console.error);
}
async function deletePreviousAlert(site) {
  	if (!site.alertMessageId) return;
  	const channel = await client.channels.fetch(ALERT_ID).catch(() => null);
  	if (!channel) return;
  	try {
    	const msg = await channel.messages.fetch(site.alertMessageId);
    	await msg.delete().catch(() => {});
  	} catch {}
  	site.alertMessageId = null;
}
async function monitorSites() {
  	for (const site of sites) {
    	let isUp = false;
    	for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
      		isUp = await checkSite(site);
      		if (isUp) break;
      		if (attempt < MAX_RETRIES) await new Promise(r => setTimeout(r, RETRY_DELAY));
    	}
    	if (isUp) {
      		site.failures = 0;
      		if (site.isDown) {
        		site.isDown = false;
        		await deletePreviousAlert(site);
        		await updateChannelName(site, true);
        		await sendAlert(`✅ **${site.name} Is Back Up**\n<@&${DT_PING}>`);
      		}
    	} else {
      		site.failures++;
      		if (site.failures >= FAILURE_THRESHOLD && !site.isDown) {
        		site.isDown = true;
        		await updateChannelName(site, false);
        		const alert = await sendAlert(
          			`🚨 **${site.name} Is DOWN**\nAffected Services: ${site.services}\n<@&${DT_PING}>`
        		);
        		if (alert) site.alertMessageId = alert.id;
      		}
    	}
  	}
}
async function retryLogin(retries = MAX_RETRIES) {
  	for (let i = 0; i < retries; i++) {
    	try {
      		await client.login(BOT_TOKEN);
      		return;
    	} catch (err) {
      		const isNetworkError = err.code === "EAI_AGAIN" || err.code === "ENOTFOUND" || err.code === "ECONNRESET";
      		if (isNetworkError) {
        		const backoff = Math.min(RETRY_DELAY * Math.pow(2, i), 5 * 60 * 1000);
        		const jitter  = Math.floor(Math.random() * 2000);
        		console.log(`Discord Login Failed (${err.code}). Retry ${i + 1}/${retries} in ${Math.round((backoff + jitter) / 1000)}s...`);
        		await new Promise(r => setTimeout(r, backoff + jitter));
      		} else {
        		console.error("Discord Login Failed:", err);
        		throw err;
      		}
    	}
  	}
  	throw new Error("Failed To Login To Discord After Multiple Retries.");
}
async function getAvatarColor(url) {
	try {
		const img = await Jimp.read(url);
		img.resize({ w: 1, h: 1 });
		const hex = img.getPixelColor(0, 0);
		const r = (hex >>> 24) & 0xff;
		const g = (hex >>> 16) & 0xff;
		const b = (hex >>> 8) & 0xff;
		return (r << 16) + (g << 8) + b;
	} catch {
		return 0x2b2d31;
	}
}
const commands = [
	addCommand(
		new SlashCommandBuilder()
			.setName("rand")
			.setDescription("Generate A Random Number")
			.addIntegerOption(option =>
				option.setName("min").setDescription("Minimum Number").setRequired(false)
			)
			.addIntegerOption(option =>
				option.setName("max").setDescription("Maximum Number").setRequired(false)
			),
		async (interaction) => {
			let min = interaction.options.getInteger("min") ?? 1;
			let max = interaction.options.getInteger("max") ?? 100;
			if (min > max) {
				return interaction.reply({
					content: "Min Cannot Be Greater Than Max.",
					flags: MessageFlags.Ephemeral
				});
			}
			const num = Math.floor(Math.random() * (max - min + 1)) + min;
			interaction.reply(`Random Number: **${num}** (Range ${min}-${max})`);
		}
	),
	addCommand(
		new SlashCommandBuilder()
			.setName("membercount")
			.setDescription("Shows The Total Member Count Of This Server"),
		async (interaction) => {
			const count = interaction.guild.memberCount;
			await interaction.reply({
				content: `Server Member Count: **${count}**`,
				flags: MessageFlags.Ephemeral
			});
		}
	),
	addCommand(
		new SlashCommandBuilder()
			.setName("invite")
			.setDescription("Shows The Invite Link For The Server"),
		async (interaction) => {
			return interaction.reply({
				content: INV_LINK,
				flags: MessageFlags.Ephemeral
			});
		}
	),
	addCommand(
		new SlashCommandBuilder()
			.setName("urls")
			.setDescription("Shows The Current Official URLs For Infinite Campus"),
		async (interaction) => {
			return interaction.reply({
				content: `Current Official Infinite Campus URLs\n\nMost Updated:\nhttps://www.infinitecampus.xyz\nhttps://instructure.space\n\nNon Working Proxy:\nhttps://backup.infinitecampus.xyz\nhttps://backup.instructure.space\n\nNon Working Proxy And No More Updates:\nhttps://infinitecampus.codehs.me`,
    			flags: MessageFlags.Ephemeral | MessageFlags.SuppressEmbeds
			})
		}
	),
	addCommand(
		new SlashCommandBuilder()
			.setName("github")
			.setDescription("Sends The Links To The Github Repos"),
		async (interaction) => {
			return interaction.reply({
				content: `Current Github Repo URLs:\n\nMain Repo URL:\nhttps://github.com/InfiniteCampus41/InfiniteCampus\n\nSubdomains Repo:\nhttps://github.com/InfiniteCampus41/Subdomains\n\nBackend Code Repo:\nhttps://github.com/InfiniteCampus41/InfiniteCampus-Core`,
				flags: MessageFlags.Ephemeral | MessageFlags.SuppressEmbeds
			})
		}
	),
	addCommand(
		new SlashCommandBuilder()
			.setName("warn")
			.setDescription("Warn A Member")
			.addUserOption(option =>
				option.setName("user").setDescription("User To Warn").setRequired(true)
			)
			.addStringOption(option =>
				option.setName("reason").setDescription("Reason For The Warning").setRequired(true)
			)
			.addStringOption(option =>
				option.setName("feedback").setDescription("Feedback For The User").setRequired(true)
			),
		async (interaction) => {
			if (!interaction.member.permissions.has("Administrator")) {
				return interaction.reply({
					content: "You Do Not Have Permission To Use This Command.",
					flags: MessageFlags.Ephemeral
				});
			}
			const WARN_ROLES = [
				WARN1,
				WARN2,
				WARN3,
				WARN4
			];
			const user = interaction.options.getUser("user");
			const reason = interaction.options.getString("reason");
			const feedback = interaction.options.getString("feedback");
			const member = await interaction.guild.members.fetch(user.id);
			let warnLevel = 0;
			for (let i = 0; i < WARN_ROLES.length; i++) {
				if (member.roles.cache.has(WARN_ROLES[i])) {
					warnLevel = i + 1;
				}
			}
			const nextWarn = warnLevel + 1;
			let consequence = "";
			let timeoutDuration = 0;
			if (nextWarn === 1) {
				timeoutDuration = 60 * 1000;
				consequence = "Timed Out For **1 Minute**";
				await member.roles.add(WARN_ROLES[0]);
			}
			else if (nextWarn === 2) {
				timeoutDuration = 10 * 60 * 1000;
				consequence = "Timed Out For **10 Minutes**";
				await member.roles.add(WARN_ROLES[1]);
			}
			else if (nextWarn === 3) {
				timeoutDuration = 60 * 60 * 1000;
				consequence = "Muted And Timed Out For **1 Hour**";
				await member.roles.add(WARN_ROLES[2]);
				const muteRole = interaction.guild.roles.cache.find(r => r.name === "Muted");
				if (muteRole) {
					await member.roles.add(muteRole);
				}
			}
			else if (nextWarn === 4) {
				timeoutDuration = 24 * 60 * 60 * 1000;
				consequence = "Timed Out For **1 Day**";
				await member.roles.add(WARN_ROLES[3]);
			}
			else if (nextWarn >= 5) {
				try {
					await user.send(`You Have Been **Banned** From **${interaction.guild.name}**\n\nWarn Count: **5**\n\nReason:\n${reason}\n\nFeedback:\n${feedback}\n\nConsequence:\n**Permanent Ban**`);
				} catch {}
				await member.ban({ reason: `Warn Level 5 | ${reason}` });
				return interaction.reply({
					content: `${user.tag} Has Been Banned (Warn Level 5).`,
					flags: MessageFlags.Ephemeral
				});
			}
			if (timeoutDuration > 0) {
				await member.timeout(timeoutDuration, reason);
			}
			try {
				await user.send(`You Have Been Warned In **${interaction.guild.name}**\n\nWarn Count: **${nextWarn}**\n\nReason:\n${reason}\n\nFeedback:\n${feedback}\n\nConsequence:\n${consequence}`);
			} catch {}
			await interaction.reply({
				content: `${user.tag} Has Been Warned. (Warn ${nextWarn}/5)`,
				flags: MessageFlags.Ephemeral
			});
		}
	),
	addCommand(
		new SlashCommandBuilder()
			.setName("showwarns")
			.setDescription("Show All Users With Warnings"),
		async (interaction) => {
			if (!interaction.member.permissions.has("Administrator")) {
				return interaction.reply({
					content: "You Do Not Have Permission To Use This Command.",
					flags: MessageFlags.Ephemeral
				});
			}
			const WARN_ROLES = [
				WARN1,
				WARN2,
				WARN3,
				WARN4
			];
			const members = await interaction.guild.members.fetch();
			let warnedUsers = [];
			members.forEach(member => {
				for (let i = WARN_ROLES.length - 1; i >= 0; i--) {
					if (member.roles.cache.has(WARN_ROLES[i])) {
						warnedUsers.push(`${member.user.tag} — Warn ${i + 1}`);
						break;
					}
				}
			});
			if (warnedUsers.length === 0) {
				return interaction.reply({
					content: "No Users Currently Have Warnings.",
					flags: MessageFlags.Ephemeral
				});
			}
			await interaction.reply({
				content: `**Users With Warnings:**\n\n${warnedUsers.join("\n")}`,
				flags: MessageFlags.Ephemeral
			});
		}
	),
	addCommand(
		new SlashCommandBuilder()
			.setName("unwarn")
			.setDescription("Remove A Warning From A User")
			.addUserOption(option =>
				option.setName("user").setDescription("User To Unwarn").setRequired(true)
			),
		async (interaction) => {
			if (!interaction.member.permissions.has("Administrator")) {
				return interaction.reply({
					content: "You Do Not Have Permission To Use This Command.",
					flags: MessageFlags.Ephemeral
				});
			}
			const WARN_ROLES = [
				WARN1,
				WARN2,
				WARN3,
				WARN4
			];
			const user = interaction.options.getUser("user");
			const member = await interaction.guild.members.fetch(user.id);
			let removedLevel = null;
			for (let i = WARN_ROLES.length - 1; i >= 0; i--) {
				if (member.roles.cache.has(WARN_ROLES[i])) {
					await member.roles.remove(WARN_ROLES[i]);
					removedLevel = i + 1;
					break;
				}
			}
			if (!removedLevel) {
				return interaction.reply({
					content: `${user.tag} Has No Warnings.`,
					flags: MessageFlags.Ephemeral
				});
			}
			await interaction.reply({
				content: `Removed Warn Level **${removedLevel}** From ${user.tag}.`,
				flags: MessageFlags.Ephemeral
			});
		}
	),
	addCommand(
		new SlashCommandBuilder()
			.setName("check")
			.setDescription("Check Your Credentials For Infinite Campus")
			.setDefaultMemberPermissions(PermissionFlagsBits.Administrator),
		async (interaction) => {
			const userId = interaction.user.id;
			let response = "Unknown User.";
			if (userId === OWNER_UID) {
				response = AD_PASS_1;
			} else if (userId === AD1_UID) {
				response = AD_PASS_2;
			} else if (userId === AD2_UID) {
				response = AD_PASS_3;
			} else {
				response = "You Do Not Have Permissions To Use This Command";
			}
			return interaction.reply({
				content: response,
				flags: MessageFlags.Ephemeral | MessageFlags.SuppressEmbeds
			});
		}
	),
	addCommand(
		new SlashCommandBuilder()
			.setName("help")
			.setDescription("Shows Available Commands"),
		async (interaction) => {
			const isAdmin = interaction.member.permissions.has(PermissionFlagsBits.Administrator);
			const userCommands = [
				"/help - Show This Menu",
				"/rand - Generate A Random Number",
				"/membercount - Show Server Member Count",
				"/invite - Get Server Invite",
				"/urls - Show Official InfiniteCampus URLs",
				"/github - Show Github Repositories"
			];
			const adminCommands = [
				"/warn",
				"/showwarns",
				"/unwarn",
				"/check",
				"/sticky",
				"/deletesticky",
				"/togglesticky",
				"/setcounting",
				"/togglecounting",
				"/ban",
				"/kick",
				"/mute",
				"/unban",
				"/announce",
				"/setnick"
			];
			let description = `**User Commands:**\n${userCommands.join("\n")}`;
			if (isAdmin) {
				description += `\n\n**Admin Commands:**\n${adminCommands.join("\n")}`;
			}
			const embed = new EmbedBuilder()
				.setTitle("Bot Command Help")
				.setDescription(description)
				.setColor(0x2b2d31);
			await interaction.reply({
				embeds: [embed],
				flags: MessageFlags.Ephemeral
			});
		}
	),
	addCommand(
		new SlashCommandBuilder()
			.setName("sticky")
			.setDescription("Set A Sticky Message For A Channel")
			.setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
			.addChannelOption(option =>
				option.setName("channel")
				.setDescription("Channel For Sticky")
				.setRequired(true)
			)
			.addStringOption(option =>
				option.setName("message")
				.setDescription("Sticky Message")
				.setRequired(true)
			),
		async (interaction) => {
			const channel = interaction.options.getChannel("channel");
			let message = interaction.options.getString("message");
			message += "\n-# This Is An Automated Sticky Message.";
			if (!vars.sticky[channel.id]) {
				vars.sticky[channel.id] = {
					message: null,
					enabled: true,
					lastMessageId: null
				};
			}
			const old = vars.sticky[channel.id].message;
			vars.sticky[channel.id].message = message;
			vars.sticky[channel.id].enabled = true;
			saveVars();
			const modlog = await client.channels.fetch(MOD_ID).catch(() => null);
			if (modlog) {
				modlog.send(
					`**Sticky Message Updated**\nUser: ${interaction.user.tag}\nChannel: ${channel.name}\n\nOld:\n${old || "None"}\n\nNew:\n${message}`
				);
			}
			await interaction.reply({
				content: `Sticky Message Set For ${channel}.`,
				flags: MessageFlags.Ephemeral
			});
		}
	),
	addCommand(
		new SlashCommandBuilder()
			.setName("deletesticky")
			.setDescription("Delete Sticky Message From A Channel")
			.setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
			.addChannelOption(option =>
				option.setName("channel")
				.setDescription("Channel")
				.setRequired(true)
			),
		async (interaction) => {
			const channel = interaction.options.getChannel("channel");
			if (!vars.sticky[channel.id]) {
				return interaction.reply({
					content: "No Sticky Message Exists For That Channel.",
					flags: MessageFlags.Ephemeral
				});
			}
			delete vars.sticky[channel.id];
			saveVars();
			await interaction.reply({
				content: `Sticky Message Deleted For ${channel}.`,
				flags: MessageFlags.Ephemeral
			});
		}
	),
	addCommand(
		new SlashCommandBuilder()
			.setName("togglesticky")
			.setDescription("Enable Or Disable Sticky Message")
			.setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
			.addChannelOption(option =>
				option.setName("channel")
				.setDescription("Channel")
				.setRequired(true)
			),
		async (interaction) => {
			const channel = interaction.options.getChannel("channel");
			if (!vars.sticky[channel.id]) {
				return interaction.reply({
					content: "No Sticky Message Exists For That Channel.",
					flags: MessageFlags.Ephemeral
				});
			}
			vars.sticky[channel.id].enabled = !vars.sticky[channel.id].enabled;
			saveVars();
			await interaction.reply({
				content: `Sticky Message Is Now **${vars.sticky[channel.id].enabled ? "Enabled" : "Disabled"}** For ${channel}.`,
				flags: MessageFlags.Ephemeral
			});
		}
	),
	addCommand(
		new SlashCommandBuilder()
			.setName("setcounting")
			.setDescription("Set The Counting Channel")
			.setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
			.addChannelOption(option =>
				option.setName("channel")
				.setDescription("Counting Channel")
				.setRequired(true)
			),
		async (interaction) => {
			const channel = interaction.options.getChannel("channel");
			vars.counting.channel = channel.id;
			vars.counting.num = 0;
			vars.counting.uid = null;
			vars.counting.enabled = true;
			saveVars();
			await interaction.reply({
				content: `Counting Channel Set To ${channel}. Counting Starts At **1**.`,
				flags: MessageFlags.Ephemeral
			});
		}
	),
	addCommand(
		new SlashCommandBuilder()
			.setName("togglecounting")
			.setDescription("Enable Or Disable The Counting Game")
			.setDefaultMemberPermissions(PermissionFlagsBits.Administrator),
		async (interaction) => {
			if (!vars.counting.channel) {
				return interaction.reply({
					content: "Counting Channel Has Not Been Set.",
					flags: MessageFlags.Ephemeral
				});
			}
			vars.counting.enabled = !vars.counting.enabled;
			saveVars();
			const channel = await client.channels.fetch(vars.counting.channel).catch(()=>null);
			if (channel) {
				channel.send(
					`Counting Game Has Been **${vars.counting.enabled ? "Enabled" : "Disabled"}**.\nNext Number: **${vars.counting.num + 1}**`
				);
			}
			await interaction.reply({
				content: `Counting Game Is Now **${vars.counting.enabled ? "Enabled" : "Disabled"}**.`,
				flags: MessageFlags.Ephemeral
			});
		}
	),
	addCommand(
		new SlashCommandBuilder()
			.setName("ban")
			.setDescription("Ban A Member")
			.setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
			.addUserOption(option =>
				option.setName("user").setDescription("User To Ban").setRequired(true)
			)
			.addStringOption(option =>
				option.setName("reason").setDescription("Reason For Ban").setRequired(true)
			)
			.addStringOption(option =>
				option.setName("feedback").setDescription("Feedback For The User").setRequired(true)
			),
		async (interaction) => {
			const user = interaction.options.getUser("user");
			const reason = interaction.options.getString("reason");
			const feedback = interaction.options.getString("feedback");
			const member = await interaction.guild.members.fetch(user.id).catch(()=>null);
			try {
				await user.send(`You Have Been **Banned** From **${interaction.guild.name}**\n\nReason:\n${reason}\n\nFeedback:\n${feedback}`);
			} catch {}
			recentlyBanned.add(user.id);
            if (member) {
                await member.ban({ reason });
            } else {
                await interaction.guild.members.ban(user.id, { reason });
            }
			await interaction.reply({
				content: `${user.tag} Has Been Banned.`,
				flags: MessageFlags.Ephemeral
			});
		}
	),
	addCommand(
		new SlashCommandBuilder()
			.setName("kick")
			.setDescription("Kick A Member")
			.setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
			.addUserOption(option =>
				option.setName("user").setDescription("User To Kick").setRequired(true)
			)
			.addStringOption(option =>
				option.setName("reason").setDescription("Reason For Kick").setRequired(true)
			)
			.addStringOption(option =>
				option.setName("feedback").setDescription("Feedback For The User").setRequired(true)
			),
		async (interaction) => {
			const user = interaction.options.getUser("user");
			const reason = interaction.options.getString("reason");
			const feedback = interaction.options.getString("feedback");
			const member = await interaction.guild.members.fetch(user.id);
			try {
				await user.send(`You Have Been **Kicked** From **${interaction.guild.name}**\n\nReason:\n${reason}\n\nFeedback:\n${feedback}`);
			} catch {}
			recentlyKicked.add(user.id);
            await member.kick(reason);
			await interaction.reply({
				content: `${user.tag} Has Been Kicked.`,
				flags: MessageFlags.Ephemeral
			});
		}
	),
	addCommand(
		new SlashCommandBuilder()
			.setName("mute")
			.setDescription("Mute A Member")
			.setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
			.addUserOption(option =>
				option.setName("user").setDescription("User To Mute").setRequired(true)
			)
			.addIntegerOption(option =>
				option.setName("minutes").setDescription("Mute Duration In Minutes").setRequired(true)
			)
			.addStringOption(option =>
				option.setName("reason").setDescription("Reason For Mute").setRequired(true)
			)
			.addStringOption(option =>
				option.setName("feedback").setDescription("Feedback For The User").setRequired(true)
			),
		async (interaction) => {
			const user = interaction.options.getUser("user");
			const minutes = interaction.options.getInteger("minutes");
			const reason = interaction.options.getString("reason");
			const feedback = interaction.options.getString("feedback");
			const member = await interaction.guild.members.fetch(user.id);
			const duration = minutes * 60 * 1000;
			const expire = Math.floor((Date.now() + duration) / 1000);
			try {
				await user.send(`You Have Been **Muted** In **${interaction.guild.name}**\n\nReason:\n${reason}\n\nFeedback:\n${feedback}\n\nMute Length:\n${minutes} Minutes\n\nMute Expires:\n<t:${expire}:F>`);
			} catch {}
			await member.timeout(duration, reason);
			await interaction.reply({
				content: `${user.tag} Has Been Muted For **${minutes} Minutes**.`,
				flags: MessageFlags.Ephemeral
			});
		}
	),
	addCommand(
		new SlashCommandBuilder()
			.setName("unban")
			.setDescription("Unban A User")
			.setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
			.addStringOption(option =>
				option.setName("userid").setDescription("User ID To Unban").setRequired(true)
			),
		async (interaction) => {
			const id = interaction.options.getString("userid");
			try {
				await interaction.guild.members.unban(id);
				await interaction.reply({
					content: `User **${id}** Has Been Unbanned.`,
					flags: MessageFlags.Ephemeral
				});
			} catch {
				await interaction.reply({
					content: "Failed To Unban That User.",
					flags: MessageFlags.Ephemeral
				});
			}
		}
	),
	addCommand(
		new SlashCommandBuilder()
			.setName("announce")
			.setDescription("Send An Announcement")
			.setDefaultMemberPermissions(PermissionFlagsBits.Administrator),
		async (interaction) => {
			const modal = new ModalBuilder()
				.setCustomId("announce_modal")
				.setTitle("Create Announcement");
			const messageInput = new TextInputBuilder()
				.setCustomId("announcement_message")
				.setLabel("Announcement Message")
				.setStyle(TextInputStyle.Paragraph)
				.setPlaceholder("Type Your Announcement Here Exactly Like A Normal Discord Message")
				.setRequired(true);
			const row = new ActionRowBuilder().addComponents(messageInput);
			modal.addComponents(row);
			await interaction.showModal(modal);
		}
	),
	addCommand(
		new SlashCommandBuilder()
			.setName("setnick")
			.setDescription("Set A User's Nickname")
			.setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
			.addUserOption(option =>
				option.setName("user")
					.setDescription("User To Change Nickname")
					.setRequired(true)
			)
			.addStringOption(option =>
				option.setName("nickname")
					.setDescription("New Nickname")
					.setRequired(true)
			),
		async (interaction) => {
			const user = interaction.options.getUser("user");
			const nickname = interaction.options.getString("nickname");
			const member = await interaction.guild.members.fetch(user.id).catch(() => null);
			if (!member) {
				return interaction.reply({
					content: "User Not Found In This Server.",
					flags: MessageFlags.Ephemeral
				});
			}
			try {
				await member.setNickname(nickname);
				await interaction.reply({
					content: `${user.tag}'s Nickname Has Been Set To **${nickname}**.`,
					flags: MessageFlags.Ephemeral
				});
			} catch (err) {
				console.error(err);
				await interaction.reply({
					content: "Failed To Change Nickname. Make Sure The Bot Role Is Higher Than The User",
					flags: MessageFlags.Ephemeral
				});
			}
		}
	),
];
async function registerCommands() {
  	const rest = new REST({ version: "10" }).setToken(BOT_TOKEN);
  	try {
    	console.log("Registering Test Commands...");
    	await rest.put(
      		Routes.applicationGuildCommands(
        		CL_ID,
        		GU_ID
      		),
      		{ body: commands }
    	);
    	console.log("Test Commands Registered Instantly.");
  	} catch (err) {
    	console.error(err);
  	}
}
client.on("interactionCreate", async interaction => {
	if (interaction.isChatInputCommand()) {
		const handler = commandHandlers[interaction.commandName];
		if (!handler) return;
		try {
			await handler(interaction);
		} catch (err) {
			console.error(err);
			interaction.reply({
				content: "Error Running Command.",
				flags: MessageFlags.Ephemeral
			});
		}
	}
	if (interaction.isModalSubmit()) {
		if (interaction.customId === "announce_modal") {
			const message = interaction.fields.getTextInputValue("announcement_message");
			const channel = await client.channels.fetch(ANNOUNCE_ID).catch(()=>null);
			if (!channel) {
				return interaction.reply({
					content: "Announcements Channel Not Found.",
					flags: MessageFlags.Ephemeral
				});
			}
			await channel.send(message);
			await interaction.reply({
				content: "Announcement Sent.",
				flags: MessageFlags.Ephemeral
			});
		}
	}
});
client.on("messageCreate", async message => {
	if (!message.guild) return;
	if (
		vars.counting.enabled &&
		message.channel.id === vars.counting.channel &&
		!message.author.bot
	) {
		if (!/^\d+$/.test(message.content)) return;
		const num = parseInt(message.content);
		const expected = vars.counting.num + 1;
		if (vars.counting.uid === message.author.id) {
			await message.react("❌");
			message.channel.send(
				`${message.author} Ruined It!\nYou Cannot Send Two Numbers In A Row.`
			);
			vars.counting.num = 0;
			vars.counting.uid = null;
			saveVars();
			return;
		}
		if (num !== expected) {
			await message.react("❌");
			message.channel.send(
				`${message.author} Ruined It!\n**${num}** Is The Wrong Number.`
			);
			vars.counting.num = 0;
			vars.counting.uid = null;
			saveVars();
			return;
		}
		await message.react("✅");
		vars.counting.num = num;
		vars.counting.uid = message.author.id;
		saveVars();
	}
	if (!vars.sticky[message.channel.id]) return;
	const sticky = vars.sticky[message.channel.id];
	if (!sticky.enabled) return;
	if (message.content === sticky.message) return;
	try {
		if (sticky.lastMessageId) {
			const old = await message.channel.messages.fetch(sticky.lastMessageId).catch(() => null);
			if (old) await old.delete().catch(() => {});
		}
		const newSticky = await message.channel.send(sticky.message);
		sticky.lastMessageId = newSticky.id;
		saveVars();
	} catch (err) {
		console.error(err);
	}
});
client.on("guildMemberAdd", async member => {
	const channel = await client.channels.fetch(JOINLEAVE_ID).catch(()=>null);
	if (!channel) return;
	const avatar = member.user.displayAvatarURL({ extension: "png", size: 512 });
	const color = await getAvatarColor(avatar);
	const accountAge = Math.floor((Date.now() - member.user.createdTimestamp) / (1000*60*60*24));
	const embed = new EmbedBuilder()
		.setTitle(`${member.user.username} Joined The Server`)
		.setDescription(`Welcome ${member.user.username} To The Server`)
		.setColor(color)
		.setImage(avatar)
		.setFooter({ text: `Account Age: ${accountAge} Days` });
	await channel.send({ embeds: [embed] });
	const count = member.guild.memberCount;
	if (count < 50) {
		try {
			const role = member.guild.roles.cache.get(OG_ID);
			if (role) {
				await member.roles.add(role);
			}
		} catch (err) {
			console.error("Failed to assign og role:", err);
		}
	}
	const countChannel = await client.channels.fetch(MEMBER_ID).catch(()=>null);
	if (countChannel) {
		const count = member.guild.memberCount;
		await countChannel.setName(`Server Members: ${count}`).catch(()=>{});
	}
});
client.on("guildMemberRemove", async member => {
    const channel = await client.channels.fetch(JOINLEAVE_ID).catch(() => null);
    if (!channel) return;
    const avatar = member.user.displayAvatarURL({ extension: "png", size: 512 });
    const wasBanned = recentlyBanned.delete(member.user.id);
    const wasKicked = !wasBanned && recentlyKicked.delete(member.user.id);
    let title, description;
    if (wasBanned) {
        title = `${member.user.username} Was Banned From The Server`;
        description = `${member.user.username} Has Been Banned`;
    } else if (wasKicked) {
        title = `${member.user.username} Was Kicked From The Server`;
        description = `${member.user.username} Has Been Kicked`;
    } else {
        title = `${member.user.username} Left The Server`;
        description = null;
    }
    const embed = new EmbedBuilder()
        .setTitle(title)
        .setColor(wasBanned ? 0xff0000 : wasKicked ? 0xff8c00 : 0xff6b6b)
        .setImage(avatar);
    if (description) embed.setDescription(description);
    await channel.send({ embeds: [embed] });
    const countChannel = await client.channels.fetch(MEMBER_ID).catch(() => null);
    if (countChannel) {
        const count = member.guild.memberCount;
        await countChannel.setName(`Server Members: ${count}`).catch(() => {});
    }
});
let monitorInterval = null;
client.once("clientReady", async () => {
  	console.log(`Logged In As ${client.user.tag}`);
  	await registerCommands();
  	for (let i = 0; i < sites.length; i++) {
    	await updateChannelName(sites[i], true);
    	if (i < sites.length - 1) await new Promise(r => setTimeout(r, 1500));
  	}
  	if (!monitorInterval) {
    	monitorInterval = setInterval(monitorSites, CHECK_INTERVAL);
  	}
});
app.listen(3000, async () => {
    console.log("Server Started On Port 3000");
    await checkSites();
    setTimeout(() => {
        checkSites();
        setInterval(checkSites, CHECK_INTERVAL_MS);
    }, msUntilNextAlignedCheck());
});
retryLogin().catch(console.error);