/* --------------------------------------------------------------------------------------------
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root for license information.
 * ------------------------------------------------------------------------------------------ */

import * as path from 'path';
import { workspace, ExtensionContext, window, commands, Uri, ViewColumn } from 'vscode';
import * as os from "node:os";
import * as fs from "node:fs";

import {
	Executable,
	LanguageClient,
	LanguageClientOptions,
	ServerOptions,
	TransportKind
} from 'vscode-languageclient/node';

let client: LanguageClient;

export function activate(context: ExtensionContext) {
	const hello = commands.registerCommand("meerkat.hello", () => {
		window.showInformationMessage("Meerkat is here!");
	});

	const executeSuricata = commands.registerCommand("meerkat.executeSuricata", (uri: Uri) => {
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

		const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "meerkat"));

		// removeFastLogs(temporaryDirectory);
		const terminalName = "Run suricata";
		const terminal = window.createTerminal(terminalName, "suricata", [
			"-S", window.activeTextEditor.document.uri.fsPath,
			"-r", uri.fsPath,
			"-l", temporaryDirectory
		]);

		window.onDidCloseTerminal(async t => {
			if (t.name === terminalName) {
				// Get configuration
				const workbenchConfig = workspace.getConfiguration("meerkat");
				const ignoreSuricata = workbenchConfig.get("ignoreSuricataErrors");
				if (t.exitStatus.code === 1) {
					const fastLog = Uri.parse(path.join(temporaryDirectory, "fast.log"));
					window.showTextDocument(fastLog, {
						"preserveFocus": true,
						"viewColumn": ViewColumn.Beside
					});
				}
				else if(!ignoreSuricata) {
					// Prompt the user
					const response = await window.showErrorMessage(`The suricata process exited with code: ${t.exitStatus.reason}(${t.exitStatus.code})`
						, ...["Open suricata logs", "Ignore", "Do not show again"]);
					// Check if the user wants to open the suricata logs
					if (response === "Open suricata logs") {
						const suricataLog = Uri.parse(path.join(temporaryDirectory, "suricata.log"));
						window.showTextDocument(suricataLog, {
							"preserveFocus": false,
							"viewColumn": ViewColumn.Active
						});
					}
					// Check if it is don't show again
					else if (response === "Do not show again") {
						workbenchConfig.update("ignoreSuricataErrors", true);
						const undo = await window.showInformationMessage("Setting has been adjusted!", "undo");
						if (undo) {
							workbenchConfig.update("ignoreSuricataErrors", true);
							const undo = await window.showInformationMessage("Change has been undone!");
						}
					}
				}
			}
		});
	});

	context.subscriptions.push(executeSuricata, hello);


	const traceOutputChannel = window.createOutputChannel("Meerkat Language Server trace");
	// const command = process.env.SERVER_PATH || "meerkat";
	const command = process.env.SERVER_PATH || path.join(__dirname, "../../target/debug/meerkat");
	const run: Executable = {
		command,
		options: {
			env: {
				...process.env,
				// eslint-disable-next-line @typescript-eslint/naming-convention
				RUST_BACKTRACE: "1",
				RUST_LOG: "debug"
			},
		},
	};
	const serverOptions: ServerOptions = {
		run,
		debug: run,
	};
	// If the extension is launched in debug mode then the debug server options are used
	// Otherwise the run options are used
	// Options to control the language client
	const clientOptions: LanguageClientOptions = {
		// Register the server for plain text documents
		documentSelector: [{ scheme: "file", language: "suricata" }],
		synchronize: {
			// Notify the server about file changes to '.clientrc files contained in the workspace
			fileEvents: workspace.createFileSystemWatcher("**/.clientrc"),
		},
		traceOutputChannel,
	};

	// Create the language client and start the client.
	client = new LanguageClient("suricata-language-server", "Suricata language server", serverOptions, clientOptions);
	client.start();
}

export function deactivate(): Thenable<void> | undefined {
	if (!client) {
		return undefined;
	}
	return client.stop();
}

function removeFastLogs(folderPath: string) {
	const fastLog = path.join(folderPath, "fast.log");
	const fastLogOld = path.join(folderPath, "fast.log.old");
	// Copy the file to old file (for usefullness)
	// fs.copyFileSync(fastLog, fastLogOld);
	// Remove logs file
	fs.unlinkSync(fastLog);
}
