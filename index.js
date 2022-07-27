import Artibot, { Module, SlashCommand } from "artibot";
import Localizer from "artibot-localizer";
import { CommandInteraction, SlashCommandBuilder } from "discord.js";
import { createRequire } from 'module';
import path from "path";
import whois from "whois";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const require = createRequire(import.meta.url);
const { version } = require('./package.json');

/**
 * WHOIS slash command
 * Extension for Artibot
 * Uses Node.js WHOIS module to get info about a domain
 * 
 * @author GoudronViande24
 * @license MIT
 * @param {Artibot} artibot
 * @returns {Module}
 */
export default ({ config: { lang } }) => {
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
	filePath: path.join(__dirname, "locales.json")
});


/**
 * Function executed when the slash command is sent
 * @param {CommandInteraction} interaction 
 * @param {Artibot} artibot 
 */
async function mainFunction(interaction, { createEmbed }) {
	await interaction.deferReply({ ephemeral: true });
	const domain = interaction.options.getString("domain");

	if (!domain.endsWith(".com") && !domain.endsWith(".net") && !domain.endsWith(".edu")) {
		const errorEmbed = createEmbed()
			.setColor("Red")
			.setTitle(`WHOIS - ${domain}`)
			.setDescription(localizer.__("`[[0]]` is not a valid domain.\nThis WHOIS only supports `.com`, `.net` and `.edu` TLDs.", { placeholders: [domain] }));

		return await interaction.editReply({
			embeds: [errorEmbed],
			ephemeral: true
		});
	};

	whois.lookup(domain, async (err, data) => {

		if (err) {
			const errorEmbed = createEmbed()
				.setColor("Red")
				.setTitle(`WHOIS - ${domain}`)
				.setDescription(localizer._("An error occured."));

			return await interaction.editReply({
				embeds: [errorEmbed],
				ephemeral: true
			});
		};

		// Delete the extra stuff at the end of the response
		data = data.substring(0, (data.indexOf("\nURL of the ICANN WHOIS Data Problem Reporting System:") - 1));

		let results = data.split("\n").reduce((obj, str, index) => {
			let strParts = str.split(":");

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
					};
				} else {
					obj[key] = value;
				};
			};

			return obj;
		}, {});

		// Check if no data is returned (domain not found)
		if (Object.keys(results).length === 0) {
			const errorEmbed = createEmbed()
				.setColor("Red")
				.setTitle(`WHOIS - ${domain}`)
				.setDescription(localizer.__("Domain `[[0]]` not found.", { placeholders: [domain] }));

			return await interaction.editReply({
				embeds: [errorEmbed],
				ephemeral: true
			});
		};

		if (typeof results.domainStatus == "string") {
			let code = results.domainStatus.split("#")[1].split(/[^A-Za-z]/)[0];
			var status = `[${code}](http://www.icann.org/epp#${code})`;
		} else {
			var status = "";
			results.domainStatus.forEach(value => {
				let code = value.split("#")[1].split(/[^A-Za-z]/)[0];
				status += `[${code}](http://www.icann.org/epp#${code})\n`;
			});
			status = status.trim();
		};

		if (typeof results.nameServer == "string") {
			var ns = results.nameServer;
		} else {
			var ns = "";
			results.nameServer.forEach(value => {
				ns += `${value}\n`;
			});
			ns = ns.trim();
		};

		if (results.registrantOrganization) {
			var name = results.registrantOrganization;
		} else if (results.registrantName) {
			var name = results.registrantName;
		} else {
			var name = localizer._("Name not found");
		};

		const embed = createEmbed()
			.setTitle(`WHOIS - ${domain}`)
			.setDescription(`${localizer.__("Here are the results for [[0]]", { placeholders: [domain] })}\n[${localizer._("See complete list online")}](https://who.is/whois/${domain})`)
			.addFields(
				{ name: localizer._("Registrar"), value: `[${results.registrar}](${results.registrarURL})`, inline: true },
				{ name: localizer._("Registrar WHOIS server"), value: results.registrarWHOISServer, inline: true },
				{ name: localizer._("Domain registration date"), value: results.creationDate, inline: true },
				{ name: localizer._("Email for abuse report"), value: results.registrarAbuseContactEmail, inline: true },
				{ name: localizer._("Domain status (ICANN)"), value: status, inline: true },
				{ name: localizer._("Owner's name"), value: name, inline: true },
				{ name: localizer._("DNSSEC status"), value: results.dnssec, inline: true },
				{ name: localizer._("DNS server(s)"), value: ns, inline: true }
			);

		if (results.reseller) {
			embed.addFields({ name: localizer._("Reseller"), value: results.reseller, inline: true });
		};

		return await interaction.editReply({
			embeds: [embed]
		});

	});
}