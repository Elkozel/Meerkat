/* --------------------------------------------------------------------------------------------
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root for license information.
 * ------------------------------------------------------------------------------------------ */

import * as path from 'path';
import { workspace, ExtensionContext, window, commands } from 'vscode';

import {
	Executable,
	LanguageClient,
	LanguageClientOptions,
	ServerOptions,
	TransportKind
} from 'vscode-languageclient/node';

let client: LanguageClient;

export function activate(context: ExtensionContext) {
	const hello = commands.registerCommand("meerkat.hello", async () => {
		window.showInformationMessage("Meerkat is here!");
	});
  
	context.subscriptions.push(hello);

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
