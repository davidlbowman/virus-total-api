import { Glob } from "bun";
import { delay } from "./delay";
import { getAnalysisResults } from "./getAnalysisResults";
import { scanFile } from "./scanFile";

interface ScanTotals {
	totalFiles: number;
	malicious: number;
	suspicious: number;
	undetected: number;
	harmless: number;
	timeout: number;
	"confirmed-timeout": number;
	failure: number;
	"type-unsupported": number;
}

interface ScanDirectoryInterface {
	directory: string;
	apiToken: string;
	tokenType: "FREE" | "PAID";
	delayMs: number;
}

export async function scanDirectory({
	directory,
	apiToken,
	tokenType,
	delayMs,
}: ScanDirectoryInterface) {
	if (!apiToken) {
		throw new Error("VIRUS_TOTAL_API_TOKEN environment variable is not set");
	}

	const totals: ScanTotals = {
		totalFiles: 0,
		malicious: 0,
		suspicious: 0,
		undetected: 0,
		harmless: 0,
		timeout: 0,
		"confirmed-timeout": 0,
		failure: 0,
		"type-unsupported": 0,
	};

	try {
		const glob = new Glob("**/*");
		const filePaths: string[] = [];

		for await (const file of glob.scan(directory)) {
			filePaths.push(`${directory}/${file}`);
		}

		totals.totalFiles = filePaths.length;
		console.log(`Found ${filePaths.length} files to scan`);

		if (tokenType === "PAID") {
			await Promise.all(
				filePaths.map(async (filePath) => {
					const result = await scanFile({
						filePath,
						apiToken,
					});
					await delay(2000);
					const results = await getAnalysisResults({
						analysisId: result.data.id,
						apiToken,
					});
					console.log(`Analysis results for ${filePath}:`, results);

					for (const key of Object.keys(results)) {
						if (key in totals) {
							totals[key as keyof ScanTotals] += (
								results as unknown as Record<string, number>
							)[key];
						}
					}
				}),
			);
			console.log("All files scanned successfully");
		} else {
			console.log("Starting sequential scan with 30-second delays");
			for (const filePath of filePaths) {
				const result = await scanFile({
					filePath,
					apiToken,
				});
				await delay(2000);
				const results = await getAnalysisResults({
					analysisId: result.data.id,
					apiToken,
				});
				console.log(`Analysis results for ${filePath}:`, results);

				for (const key of Object.keys(results)) {
					if (key in totals) {
						totals[key as keyof ScanTotals] += (
							results as unknown as Record<string, number>
						)[key];
					}
				}

				if (filePath !== filePaths[filePaths.length - 1]) {
					console.log(`Waiting ${delayMs / 1000} seconds before next scan...`);
					await delay(delayMs);
				}
			}
			console.log("Sequential scan completed");
		}

		console.log("\nScan Summary:");
		console.log("=============");
		console.log(`Total Files Scanned: ${totals.totalFiles}`);
		console.log(`Malicious: ${totals.malicious}`);
		console.log(`Suspicious: ${totals.suspicious}`);
		console.log(`Undetected: ${totals.undetected}`);
		console.log(`Harmless: ${totals.harmless}`);
		console.log(`Timeout: ${totals.timeout}`);
		console.log(`Confirmed Timeout: ${totals["confirmed-timeout"]}`);
		console.log(`Failures: ${totals.failure}`);
		console.log(`Type Unsupported: ${totals["type-unsupported"]}`);
	} catch (error) {
		console.error("Error scanning directory:", error);
		process.exit(1);
	}
}
