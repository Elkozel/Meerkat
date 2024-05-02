import * as path from 'path';
import { workspace, window, Uri, ViewColumn, TextDocument, StatusBarAlignment, commands, ProgressOptions, ProgressLocation, Progress } from 'vscode';
import * as os from "node:os";
import * as fs from "node:fs";
import * as util from "util";
// eslint-disable-next-line @typescript-eslint/no-var-requires
const exec = util.promisify(require('child_process').exec);

const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "meerkat"));

const opt: ProgressOptions = {
	location: ProgressLocation.Notification
};


export function executeSuricata(pcap: Uri, rules?: Uri, removeLogs = true) {
	// Return if no active file was found
	if (window.activeTextEditor === undefined) {
		window.showErrorMessage("No active rule file is selected, please open a rule file");
		return;
	}
	//Return if no file is selected from the context menu
	if (pcap === undefined) {
		window.showErrorMessage("No pcap file was, please select a pcap file");
		return;
	}

	// Set the rules if they are not set
	rules = rules ?? window.activeTextEditor.document.uri;
	// Check if the file is actually a rules file
	const rulesFile = rules.fsPath;
	if (!rulesFile.trim().endsWith("rule") && !rulesFile.trim().endsWith("rules")) {
		window.showWarningMessage("The file which is active does not have the rules extension!");
	}

	window.withProgress(opt, async (p, token) => {
		// Remove previous logs
		p.report({
			message: "Removing fast logs"
		});
		if (removeLogs) {
			removeFastLogs(temporaryDirectory);
		}
		// Create and run the teminal
		p.report({
			message: "Running suricata"
		});
		const terminalName = "Run suricata";
		const terminal = window.createTerminal(terminalName, "suricata", [
			"-S", rules.fsPath,
			"-r", pcap.fsPath,
			"-l", temporaryDirectory
		]);

		// Open log file after terminal closes
		// This section is wrapped in a promise
		const waitForTerminal = new Promise<void>((resolve, reject) => {
			window.onDidCloseTerminal(t => {
				if (t.name === terminal.name) {
					// Send a notification, that the suricata process finished
					resolve();
					// Get configuration
					const workbenchConfig = workspace.getConfiguration("meerkat");
					const ignoreSuricata = workbenchConfig.get("ignoreSuricataErrors");
					if (t.exitStatus.code === 0) {
						// Open fast log
						const fastLogUri = Uri.parse(path.join("file:\\\\" + temporaryDirectory, "fast.log"), true);
						window.showTextDocument(fastLogUri, {
							"preserveFocus": true,
							"viewColumn": ViewColumn.Beside,
							"preview": true,
						});
					}
					else if (!ignoreSuricata) {
						// Prompt the user
						window.showErrorMessage(`The suricata process exited with code: ${t.exitStatus.reason}(${t.exitStatus.code})`
							, ...["Open suricata logs", "Ignore", "Do not show again"])
							.then(response => {
								switch (response) {
									// Check if the user wants to open the suricata logs
									case "Open suricata logs":
										// eslint-disable-next-line no-case-declarations
										const suricataLog = Uri.parse(path.join("file:\\\\" + temporaryDirectory, "suricata.log"));
										window.showTextDocument(suricataLog, {
											"preserveFocus": false,
											"viewColumn": ViewColumn.Active
										});
										break;
									// Check if it is don't show again
									case "Do not show again":
										workbenchConfig.update("ignoreSuricataErrors", true);
										window.showInformationMessage("Setting has been adjusted!", "undo").then(() => {
											// If this function is executing, that means the undo button was touched
											workbenchConfig.update("ignoreSuricataErrors", false);
											window.showInformationMessage("Change has been undone!");
										});
										break;
								}
							});
					}
				}
			});

		});
		return waitForTerminal;
	});
}



export function removeFastLogs(folderPath: string) {
	const fastLog = path.join(folderPath, "fast.log");
	const fastLogOld = path.join(folderPath, "fast.log.old");
	if (fs.existsSync(fastLog)) {
		// Copy the file to old file (for usefullness)
		fs.copyFileSync(fastLog, fastLogOld);
		// Remove logs file
		fs.truncateSync(fastLog, 0);
	}
}

function searchForTextDocument(find: TextDocument) {
	return window.visibleTextEditors.findIndex(editor => {
		editor.document.fileName == find.fileName;
	}) == -1;
}

export interface SuricataInfo {
	version: string,
	asService: boolean
}
export async function getSuricataInfo(): Promise<SuricataInfo | null> {
	try {
		const { stdout, stderr } = await exec("suricata -V");
		/*
			18/5/2023 -- 22:36:55 - <Info> - Running as service: no 
			This is Suricata version 6.0.9 RELEASE
		*/
		const commandLines: string[] = stdout.split('\n');
		// Extract the "Running as a service"
		let position = commandLines[0].indexOf("Running as service:") + "Running as service:".length;
		const serviceBoolText = commandLines[0].substring(position).trim();
		const serviceBool = serviceBoolText === "yes" ? true : false;
		// Extract the version of suricata
		position = commandLines[1].indexOf("Suricata version") + "Suricata version".length;
		const suricataVersion = commandLines[1].substring(position).trim();
		return {
			"asService": serviceBool,
			"version": suricataVersion
		};
	}
	catch (err) {
		console.log(`Checking suricata produced the following error: ${err}`);
		return null;
	}
}