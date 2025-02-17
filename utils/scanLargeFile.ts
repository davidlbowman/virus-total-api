import {
	API_ENDPOINTS,
	EnvironmentVariableError,
	type ScanResult,
} from "./types";

interface ScanLargeFileOptions {
	file: Blob;
	fileName: string;
	apiToken: string | undefined;
}

export async function scanLargeFile({
	file,
	fileName,
	apiToken,
}: ScanLargeFileOptions): Promise<ScanResult> {
	if (!apiToken) {
		throw new EnvironmentVariableError("VIRUS_TOTAL_API_TOKEN is not set");
	}

	try {
		const urlResponse = await fetch(API_ENDPOINTS.LARGE, {
			headers: {
				"x-apikey": apiToken,
			},
		});

		if (!urlResponse.ok) {
			throw new Error(`Failed to get upload URL: ${urlResponse.statusText}`);
		}

		const { data: uploadUrl } = await urlResponse.json();

		const formData = new FormData();
		formData.append("file", file);

		const uploadResponse = await fetch(uploadUrl, {
			method: "POST",
			body: formData,
		});

		if (!uploadResponse.ok) {
			throw new Error(
				`Error uploading large file: ${uploadResponse.statusText}`,
			);
		}

		const result = await uploadResponse.json();
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
