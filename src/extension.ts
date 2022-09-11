import * as vscode from 'vscode';
import { parseRule } from './parse';

export function activate(context: vscode.ExtensionContext) {
	console.log('Meerkat is active!');

	let hello = vscode.commands.registerCommand('meerkat.hello', () => {
		vscode.window.showInformationMessage('Meerkat: Hi!');
	});
	context.subscriptions.push(hello);

	
}

vscode.languages.registerDocumentFormattingEditProvider('suricata', {
	provideDocumentFormattingEdits(document: vscode.TextDocument): vscode.TextEdit[] {
		var ret = [];
		var error: number[] = [];
		var linesToFormat: IterableIterator<number>;

		if (vscode.workspace.getConfiguration().get("suricata.formatActiveLineOnly")) {
			let activeTextEditor = vscode.window.activeTextEditor;
			if (!activeTextEditor) {
				vscode.window.showErrorMessage(`Meerkat: Please select a line to format first`);
				return [];
			}
			linesToFormat = Array.from<number>([activeTextEditor.selection.active.line]).values();
		}
		else {
			linesToFormat = Array<number>(document.lineCount).keys();
		}
		for (const lineNum of linesToFormat) {
			let line = document.lineAt(lineNum);
			try {
				if (line.text.length === 0 || line.text.startsWith("#")) // commented out rules
					continue;
				let formatted = parseRule(line.text);
				ret.push(vscode.TextEdit.replace(line.range, formatted.toRule()));
			} catch (err) {
				error.push(lineNum);
			}
		}
		if (error.length !== 0)
			vscode.window.showErrorMessage(`Meerkat: Could not parse rules on lines [${error}]`);
		else
			vscode.window.showInformationMessage(`Meerkat: Successfully formatted ${ret.length} lines`);
		return ret;
	}
});
