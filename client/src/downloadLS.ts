import { accessSync, chmod, createWriteStream, existsSync, mkdir } from 'fs';
import * as https from "https";
import { platform } from "process";
import * as os from "os";
import { URI } from 'vscode-languageclient';
import path = require('node:path');
import { access, constants } from 'fs/promises';
import { ProgressLocation, ProgressOptions, window } from 'vscode';

// Information needed to create the download link
const GITHUB_DOMAIN = "https://github.com";
const GITHUB_USER = "Elkozel";
const GITHUB_REPOSITORY = "Meerkat";

// Information about the language server
const LS_FOLDER = path.join(__dirname, "../../server/");

function getFilename() {
	switch (platform) {
		case "win32": return "meerkat.exe";
		case "linux": return "meerkat";
		default: throw new Error(`Could not determine fileName for platform ${platform}`);
	}
}

/**
 * Downloads a file from a GitHub release
 * @param fileName the name of the file which needs to be downloaded
 */
function downloadFromRelease(fileName: string) {
	const LS_LOC = path.join(LS_FOLDER, fileName);
	const downloadLink: string = `${GITHUB_DOMAIN}/${GITHUB_USER}/${GITHUB_REPOSITORY}/latest/releases/download/${fileName}`;

	// Create the folder
	mkdir(LS_LOC, { recursive: true }, (err) => {
		if (err) throw err;
		console.log("Server folder was created");
	});

	// Download the 
	const file = createWriteStream(LS_LOC);
	try {
		https.get(downloadLink, (response) => {
			response.pipe(file);

			// after download completed close filestream and change the rights of the file
			file.on("finish", () => {
				file.close();
				console.log("Download Completed");
			});
		});
	}
	catch (err) {
		console.error(`Encountered error while downloading file ${downloadLink}: ${err}`);
	}
}

/**
 * Changes the rights to the server
 * @param fileName the filename of the server
 */
function changeRights(fileName: string) {
	chmod(fileName, 0x775, (err) => {
		if (err) throw err;
		console.log(`The permissions for file ${fileName} have been changed!`);
	});
}


/**
 * Checks whether the language server is ready
 * @param fileName the filename for the language server
 * @returns -1 if the file does not exist, -2 if the file exists, but does not have the correct rights, 0 otherwise
 */
function checkLSReady(fileName: string) {
	const LS_LOC = path.join(LS_FOLDER, fileName);
	// Check if it exists
	if (!existsSync(LS_LOC))
		return -1; // File does not exist
	// Check if the file has the right access
	try {
		accessSync(LS_LOC, constants.X_OK);
	}
	catch (err) {
		return -2; // File does not have execute rights
	}

	// Else the file should exist and should have execute rights
	return 0;
}

const opt: ProgressOptions = {
	location: ProgressLocation.Notification,
	title: "Downloading Language Server"
};


export async function checkLS() {
	await window.withProgress(opt, async (p, token) => {
		try {
			// Get the filename
			const fileName = getFilename();

			// Check if changes are needed
			switch (checkLSReady(fileName)) {
				case 0:
					p.report({
						message: "Language Server found",
						increment: 100
					});
					break;

				case -1:
					p.report({
						message: "Downloading language server",
						increment: 20
					});
					downloadFromRelease(fileName);
					p.report({
						message: "Language server downloaded",
						increment: 60
					});

				// eslint-disable-next-line no-fallthrough
				case -2:
					p.report({
						message: "Adjusting file rights",
						increment: 10
					});
					changeRights(fileName);
					p.report({
						message: "File rights adjusted",
						increment: 10
					});
					break;
				default:
					window.showErrorMessage(`Checking language server resulted in unknown result code ${checkLSReady(fileName)}`);
			}
		} catch (err) {
			window.showErrorMessage(`Checking language server exited with an error ${err}`);
			return;
		}
	});
}