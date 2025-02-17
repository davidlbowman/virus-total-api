export const API_ENDPOINTS = {
	STANDARD: "https://www.virustotal.com/api/v3/files",
	LARGE: "https://www.virustotal.com/api/v3/files/upload_url",
	ANALYSIS: "https://www.virustotal.com/api/v3/analyses/",
} as const;

export type ScanResult = {
	success: boolean;
	id?: string;
	error?: string;
};

export class VirusTotalError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "VirusTotalError";
	}
}

export class EnvironmentVariableError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "EnvironmentVariableError";
	}
}
