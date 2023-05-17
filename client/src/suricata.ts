import * as path from 'path';
import { workspace, window, Uri, ViewColumn, TextDocument } from 'vscode';
import * as os from "node:os";
import * as fs from "node:fs";

const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "meerkat"));

export function executeSuricata(uri: Uri) {
	// Return if no active file was found
	if (window.activeTextEditor === undefined) {
		window.showErrorMessage("No active rule file is selected, please open a rule file");
		return;
	}
	//Return if no file is selected from the context menu
	if (uri === undefined) {
		window.showErrorMessage("No pcap file was, please select a pcap file");
		return;
	}
	// Check if the file is actually a rules file
	const rulesFile = window.activeTextEditor.document.uri.fsPath;
	if (!rulesFile.trim().endsWith("rule") && !rulesFile.trim().endsWith("rules")) {
		window.showWarningMessage("The file which is active does not have the rules extension!");
	}

	// Remove previous logs
	removeFastLogs(temporaryDirectory);
	// Create and run the teminal
	const terminalName = "Run suricata";
	window.createTerminal(terminalName, "suricata", [
		"-S", window.activeTextEditor.document.uri.fsPath,
		"-r", uri.fsPath,
		"-l", temporaryDirectory
	]);

	// Open log file after terminal closes
	window.onDidCloseTerminal(async t => {
		if (t.name === terminalName) {
			// Get configuration
			const workbenchConfig = workspace.getConfiguration("meerkat");
			const ignoreSuricata = workbenchConfig.get("ignoreSuricataErrors");
			if (t.exitStatus.code === 0) {
				// Open fast log
				const fastLogUri = Uri.parse(path.join("file:\\\\" + temporaryDirectory, "fast.log"), true);
				const opennedWindow = await window.showTextDocument(fastLogUri, {
					"preserveFocus": true,
					"viewColumn": ViewColumn.Beside,
					"preview": true,
				});
				console.log(searchForTextDocument(opennedWindow.document));
			}
			else if (!ignoreSuricata) {
				// Prompt the user
				window.showErrorMessage(`The suricata process exited with code: ${t.exitStatus.reason}(${t.exitStatus.code})`
					, ...["Open suricata logs", "Ignore", "Do not show again"])
					.then(response => {
						switch (response) {
							// Check if the user wants to open the suricata logs
							case "Open suricata logs":
								const suricataLog = Uri.parse(path.join(temporaryDirectory, "suricata.log"));
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