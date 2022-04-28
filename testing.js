import Artibot from "artibot";
import artibotWhois from "./index.js";

const artibot = new Artibot({
	ownerId: "382869186042658818",
	testGuildId: "775798875356397608",
	botName: "Artibot [DEV]",
	lang: "fr"
});

artibot.registerModule(artibotWhois);

artibot.login({
	token: process.env.TESTING_DISCORD_TOKEN
});