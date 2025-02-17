import { API_ENDPOINTS, EnvironmentVariableError } from "./types";

interface GetAnalysisResultsOptions {
	analysisId: string;
	apiToken: string | undefined;
}

export interface VirusTotalAnalysisResult {
	category:
		| "confirmed-timeout"
		| "timeout"
		| "failure"
		| "harmless"
		| "undetected"
		| "suspicious"
		| "malicious"
		| "type-unsupported";
	engine_name: string;
	engine_version: string;
	engine_update: string;
	method: string;
	result: string | null;
}

export interface VirusTotalStats {
	"confirmed-timeout": number;
	failure: number;
	harmless: number;
	malicious: number;
	suspicious: number;
	timeout: number;
	"type-unsupported": number;
	undetected: number;
}

export interface VirusTotalAnalysis {
	data: {
		attributes: {
			date: number;
			results: Record<string, VirusTotalAnalysisResult>;
			stats: VirusTotalStats;
			status: "completed" | "queued" | "in-progress";
		};
		id: string;
		type: "analysis";
	};
}

export async function getAnalysisResults({
	analysisId,
	apiToken,
}: GetAnalysisResultsOptions): Promise<VirusTotalAnalysis> {
	if (!apiToken) {
		throw new EnvironmentVariableError("VIRUS_TOTAL_API_TOKEN is not set");
	}

	const response = await fetch(`${API_ENDPOINTS.ANALYSIS}${analysisId}`, {
		headers: {
			"x-apikey": apiToken,
		},
	});

	if (!response.ok) {
		throw new Error(`Error getting analysis: ${response.statusText}`);
	}

	const result = await response.json();
	return result.data.attributes.stats;
}
