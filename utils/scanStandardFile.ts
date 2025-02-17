import {
	API_ENDPOINTS,
	EnvironmentVariableError,
	type ScanResult,
} from "./types";

interface ScanStandardFileOptions {
	file: Blob;
	fileName: string;
	apiToken: string | undefined;
}

export async function scanStandardFile({
	file,
	fileName,
	apiToken,
}: ScanStandardFileOptions): Promise<ScanResult> {
	if (!apiToken) {
		throw new EnvironmentVariableError("VIRUS_TOTAL_API_TOKEN is not set");
	}

	try {
		const formData = new FormData();
		formData.append("file", file);

		const response = await fetch(API_ENDPOINTS.STANDARD, {
			method: "POST",
			headers: {
				"x-apikey": apiToken,
			},
			body: formData,
		});

		if (!response.ok) {
			throw new Error(`Error scanning file: ${response.statusText}`);
		}

		const result = await response.json();
		return {
			success: true,
			id: result.data.id,
		};
	} catch (error) {
		return {
			success: false,
			error: error instanceof Error ? error.message : "Unknown error",
		};
	}
}
