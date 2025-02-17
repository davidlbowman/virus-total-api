import { scanLargeFile } from "./scanLargeFile";
import { scanStandardFile } from "./scanStandardFile";
import { VirusTotalError } from "./types";

const MAX_STANDARD_FILE_SIZE = 32 * 1024 * 1024;

export interface VirusTotalScanResponse {
	data: {
		type: string;
		id: string;
	};
}

export interface ScanFileInterface {
	filePath: string;
	apiToken: string | undefined;
}

export async function scanFile({
	filePath,
	apiToken,
}: ScanFileInterface): Promise<VirusTotalScanResponse> {
	try {
		const file = Bun.file(filePath);
		const fileSize = await file.size;
		const fileName = file.name || filePath.split("/").pop() || "unknown";

		console.log(
			`Processing ${fileName} (${(fileSize / 1024 / 1024).toFixed(2)}MB)`,
		);

		const result =
			fileSize > MAX_STANDARD_FILE_SIZE
				? await scanLargeFile({
						file,
						fileName,
						apiToken,
					})
				: await scanStandardFile({
						file,
						fileName,
						apiToken,
					});

		return {
			data: {
				type: "file",
				id: result.id || "",
			},
		};
	} catch (error) {
		throw new VirusTotalError(`Error processing ${filePath}`);
	}
}
