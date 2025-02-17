import { scanDirectory } from "./utils/scanDirectory";

const VIRUS_TOTAL_API_TOKEN = process.env.VIRUS_TOTAL_API_TOKEN;
const VIRUS_TOTAL_TOKEN_TYPE: "FREE" | "PAID" = "FREE";
const DIRECTORY_TO_SCAN = "";
const FREE_TIER_DELAY = 30000;

if (!VIRUS_TOTAL_API_TOKEN) process.exit(1);

scanDirectory({
	directory: DIRECTORY_TO_SCAN,
	apiToken: VIRUS_TOTAL_API_TOKEN,
	tokenType: VIRUS_TOTAL_TOKEN_TYPE,
	delayMs: FREE_TIER_DELAY,
});
