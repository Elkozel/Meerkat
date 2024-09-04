import { accessSync, chmod, createWriteStream, existsSync, mkdir, mkdirSync } from 'fs';
import * as https from "https";
import { platform } from "process";
import * as os from "os";
import { URI } from 'vscode-languageclient';
import path = require('node:path');
import { access, constants } from 'fs/promises';
import { ProgressLocation, ProgressOptions, window } from 'vscode';
import { DownloaderHelper } from 'node-downloader-helper';

// Information about the language server
const LS_FOLDER = path.join(__dirname, "../../server/");

function getFileName() {
	switch (platform) {
		case "win32": return "meerkat.exe";
		case "linux": return "meerkat";
		default: throw new Error(`Could not determine fileName for platform ${platform}`);
	}
}

/**
 * Checks whether the language server executable exists
 * @param fileName the name of the language server executable
 * @returns true, if the language server exists, false otherwise
 */
function LSExists(fileName: string) {
	const LS_LOC = path.join(LS_FOLDER, fileName);
	return existsSync(LS_LOC);
}
/**
 * Downloads a file from a GitHub release
 * @param fileName the name of the file which needs to be downloaded
 */
function downloadFromRelease(fileName: string) {
	const LS_LOC = path.join(LS_FOLDER, fileName);
	const downloadLink: string = `https://github.com/Elkozel/Meerkat/releases/latest/download/${fileName}`;

	// Create the folder
	if (!existsSync(LS_FOLDER))
		console.log(mkdirSync(LS_FOLDER, { recursive: true }));

	// Download the language server
	const dh = new DownloaderHelper(downloadLink, LS_FOLDER);

	return dh;
}

/**
 * Checks whether the rights for the executable are correct
 * @param fileName the name of the language server executable
 * @returns true, if the rights are correct, false otherwise
 */
function checkRights(fileName: string) {
	const LS_LOC = path.join(LS_FOLDER, fileName);
	try {
		accessSync(LS_LOC, constants.X_OK);
	}
	catch (err) {
		return false; // File does not have execute rights
	}
	return true;
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

const opt: ProgressOptions = {
	location: ProgressLocation.Notification,
	title: "Checking Language Server"
};
export async function checkLS() {
	await window.withProgress(opt, async (p, token) => {
		try {
			// Get the filename
			const fileName = getFileName();

			// Check if changes are needed
			// Download the server if needed
			if (!LSExists(fileName)) {
				const dh = downloadFromRelease(fileName);

				dh.on('download', (e) =>
					p.report({
						message: "Starting language server download",
						increment: 20
					}));
				dh.on('progress.throttled', (e) =>
					p.report({
						message: `Downloading ${e.progress}%`,
					}));

				dh.on('end', (e) =>
					p.report({
						message: "Language server downloaded",
						increment: 60
					}));

				await dh.start();
			}

			// Change file rights if needed
			if (!checkRights(fileName)) {
				p.report({
					message: "Adjusting file rights",
					increment: 10
				});
				changeRights(fileName);
				p.report({
					message: "File rights adjusted",
					increment: 10
				});
			}
		} catch (err) {
			window.showErrorMessage(`Checking language server exited with an error ${err}`);
		}
	});
}