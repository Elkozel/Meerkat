/* --------------------------------------------------------------------------------------------
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root for license information.
 * ------------------------------------------------------------------------------------------ */

import * as path from 'path';
import { workspace, ExtensionContext, window, commands, Uri, TextDocument } from 'vscode';
import * as os from "node:os";
import * as fs from "node:fs";

import {
	Executable,
	LanguageClient,
	LanguageClientOptions,
	ServerOptions
} from 'vscode-languageclient/node';
import { PcapFile, PcapProvider } from './pcapTree';
import { executeSuricata } from "./suricata";
import { SuricataStatusBar } from './statusBar';

let client: LanguageClient;

export function activate(context: ExtensionContext) {
	const hello = commands.registerCommand("meerkat.hello", () => {
		window.showInformationMessage("Meerkat is here!");
	});

	// Register the tree view
	new PcapProvider(context);
	// Register the staus bar
	new SuricataStatusBar();
	// Register execute suricata command
	const executeSuricataCommand = commands.registerCommand("meerkat.executeSuricata", (uri: Uri) => executeSuricata(uri));
	context.subscriptions.push(executeSuricataCommand, hello);


	const traceOutputChannel = window.createOutputChannel("Meerkat Language Server trace");
	// If the process environment SERVER_PATH is specified, use it, otherwise the executable should be in the default 
	const command = process.env.SERVER_PATH ? path.join(__dirname, process.env.SERVER_PATH) : path.join(__dirname, "../../server/meerkat");
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
	// Options to control the language clien t
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



function searchForTextDocument(find: TextDocument) {
	return window.visibleTextEditors.findIndex(editor => {
		editor.document.fileName == find.fileName;
	}) == -1;
}