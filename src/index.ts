import Artibot, { Module, SlashCommand, log } from "artibot";
import Localizer from "artibot-localizer";
import { ChatInputCommandInteraction, SlashCommandBuilder, EmbedBuilder } from "discord.js";
import { createRequire } from 'module';
import path from "path";
// @ts-ignore
import whois from "whois";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const require = createRequire(import.meta.url);
const { version } = require('../package.json');

/**
 * WHOIS slash command
 * Extension for Artibot
 * Uses Node.js WHOIS module to get info about a domain
 *
 * @author GoudronViande24
 * @license MIT
 */
export default ({ config: { lang } }: Artibot): Module => {
	localizer.setLocale(lang);

	return new Module({
		id: "whois",
		name: "WHOIS",
		version,
		langs: [
			"en",
			"fr"
		],
		repo: "GoudronViande24/artibot-whois",
		packageName: "artibot-whois",
		parts: [
			new SlashCommand({
				id: "whois",
				data: new SlashCommandBuilder()
					.setName("whois")
					.setDescription(localizer._("Get info on a domain"))
					.addStringOption(option =>
						option.setName("domain")
							.setDescription(localizer._("The domain to verify"))
							.setRequired(true)
					),
				mainFunction
			})
		]
	});
}

const localizer = new Localizer({
	filePath: path.join(__dirname, "../locales.json")
});


/** Function executed when the slash command is sent */
async function mainFunction(interaction: ChatInputCommandInteraction<"cached">, { createEmbed }: Artibot): Promise<void> {
	await interaction.deferReply({ ephemeral: true });
	const domain: string = interaction.options.getString("domain", true);

	if (!domain.endsWith(".com") && !domain.endsWith(".net") && !domain.endsWith(".edu")) {
		const errorEmbed: EmbedBuilder = createEmbed()
			.setColor("Red")
			.setTitle(`WHOIS - ${domain}`)
			.setDescription(localizer.__("`[[0]]` is not a valid domain.\nThis WHOIS only supports `.com`, `.net` and `.edu` TLDs.", { placeholders: [domain] }));

		await interaction.editReply({
			embeds: [errorEmbed]
		});
		return;
	}

	const result: string | false = await doWhois(domain);

	if (!result) {
		const errorEmbed = createEmbed()
			.setColor("Red")
			.setTitle(`WHOIS - ${domain}`)
			.setDescription(localizer._("An error occured."));

		await interaction.editReply({
			embeds: [errorEmbed]
		});
		return;
	}

	// Delete the extra stuff at the end of the response
	const data: string = result.substring(0, (result.indexOf("\nURL of the ICANN WHOIS Data Problem Reporting System:") - 1));

	const results: {
		registrantOrganization?: string;
		registrantName?: string;
		domainStatus?: string | string[];
		nameServer?: string | string[];
		registrar?: string;
		registrarURL?: string;
		registrarWHOISServer?: string;
		creationDate?: string;
		registrarAbuseContactEmail?: string;
		dnssec?: string;
		reseller?: string;
	} = data.split("\n").reduce((obj, str, index) => {
		const strParts = str.split(":");

		if (strParts[0] && strParts[1]) {
			let [key, ...rest] = str.split(':');
			key = key.replace(/\s+/g, '');
			if (key !== key.toUpperCase()) key = key.charAt(0).toLowerCase() + key.slice(1) // Make first letter lowercase
			else key = key.toLowerCase(); // Make the key all lowercase if it's an acronym
			let value = rest.join(':').trim();

			// Check if key already exists
			if (key in obj) {
				// Check if value is a string
				if (typeof obj[key] == "string") {
					obj[key] = [obj[key], value];
				} else { // Else add value to the array
					obj[key].push(value);
				}
			} else {
				obj[key] = value;
			}
		}

		return obj;
	}, {});

	// Check if no data is returned (domain not found)
	if (Object.keys(results).length === 0) {
		const errorEmbed = createEmbed()
			.setColor("Red")
			.setTitle(`WHOIS - ${domain}`)
			.setDescription(localizer.__("Domain `[[0]]` not found.", { placeholders: [domain] }));

		await interaction.editReply({
			embeds: [errorEmbed]
		});
		return;
	}

	let status: string;
	let ns: string;
	let name: string;

	if (typeof results.domainStatus == "string") {
		let code = results.domainStatus.split("#")[1].split(/[^A-Za-z]/)[0];
		status = `[${code}](http://www.icann.org/epp#${code})`;
	} else if (!results.domainStatus) {
		status = localizer._("Unknown status");
	} else {
		status = "";
		results.domainStatus.forEach(value => {
			let code = value.split("#")[1].split(/[^A-Za-z]/)[0];
			status += `[${code}](http://www.icann.org/epp#${code})\n`;
		});
		status = status.trim();
	}

	if (typeof results.nameServer == "string") {
		ns = results.nameServer;
	} else if (!results.nameServer) {
		ns = localizer._("No nameservers");
	} else {
		ns = "";
		results.nameServer.forEach(value => {
			ns += `${value}\n`;
		});
		ns = ns.trim();
	}

	if (results.registrantOrganization) {
		name = results.registrantOrganization;
	} else if (results.registrantName) {
		name = results.registrantName;
	} else {
		name = localizer._("Name not found");
	}

	const embed = createEmbed();

	try {
		embed
			.setTitle(`WHOIS - ${domain}`)
			.setDescription(
				localizer.__("Here are the results for [[0]]", { placeholders: [domain] }) +
				`\n[${localizer._("See complete list online")}](https://who.is/whois/${domain})`
			);
		if (results.registrar) embed.addFields({ name: localizer._("Registrar"), value: `[${results.registrar}](${results.registrarURL})`, inline: true });
		if (results.registrarWHOISServer) embed.addFields({ name: localizer._("Registrar WHOIS Server"), value: results.registrarWHOISServer, inline: true });
		if (results.creationDate) embed.addFields({ name: localizer._("Domain registration date"), value: results.creationDate, inline: true });
		if (results.registrarAbuseContactEmail) embed.addFields({ name: localizer._("Email for abuse report"), value: results.registrarAbuseContactEmail, inline: true });
		embed.addFields(
			{ name: localizer._("Domain status (ICANN)"), value: status, inline: true },
			{ name: localizer._("Owner's name"), value: name, inline: true }
		);
		if (results.dnssec) embed.addFields({ name: localizer._("DNSSEC status"), value: results.dnssec, inline: true });
		embed.addFields({ name: localizer._("DNS server(s)"), value: ns, inline: true });
		if (results.reseller) embed.addFields({ name: localizer._("Reseller"), value: results.reseller, inline: true });
	} catch (e) {
		log("WHOIS", e, "err");
		await interaction.editReply({
			embeds: [
				createEmbed()
					.setColor("Red")
					.setTitle("WHOIS")
					.setDescription(localizer._("An error occured."))
			]
		});
		return;
	}

	await interaction.editReply({
		embeds: [embed]
	});
}

function doWhois(domain: string): Promise<string | false> {
	return new Promise((resolve) => {
		whois.lookup(domain, (err: any, data: string) => {
			if (err) {
				resolve(false);
			} else {
				resolve(data);
			}
		});
	});
}