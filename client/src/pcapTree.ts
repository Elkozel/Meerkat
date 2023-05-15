import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

export class Pcap extends vscode.TreeItem {
	filepath: vscode.Uri;

	constructor(filepath: vscode.Uri) {
		let name = path.basename(filepath.fsPath, ".pcap");
		super(name, vscode.TreeItemCollapsibleState.None);
		this.filepath = filepath;
	}
}

export class PcapProvider implements vscode.TreeDataProvider<Pcap> {
	filePcapStorage: Pcap[]; // pcap files detected inside the root folder
	additionalPcapStorage: Pcap[]; // pcaps, which were additionally added by the user
	rootFolder: vscode.Uri;

	constructor(private root: vscode.Uri) {
		this.rootFolder = root;
		this.filePcapStorage = getPcaps(root);
		this.additionalPcapStorage = [];
	}

	/**
	 * Refresh the pcap files, found inside the folder
	 */
	refresh() {
		this.filePcapStorage = getPcaps(this.rootFolder);
	}

	/**
	 * Change the folder where the pcap files are detected and refresh
	 */
	rebase(filepath: vscode.Uri) {
		this.rootFolder = filepath;
		this.refresh();
	}

	/**
	 * Add an aditional pcap file
	 * @param filepath the filepath of the additional file
	 */
	async addFile(filepath?: vscode.Uri) {
		if (filepath) {
			this.additionalPcapStorage.push(new Pcap(filepath));
			return;
		}
		// else the filepath was not specified, so we need to ask the user
		let userResponse = await vscode.window.showOpenDialog({
			canSelectMany: true,
			title: "Please select the pcap files you wish to add",
			filters: {"Pcap files": ["pcap"]}
		})
		userResponse.forEach(file => {
			this.additionalPcapStorage.push(new Pcap(file))
		})
	}

	onDidChangeTreeData?: vscode.Event<void | Pcap | Pcap[]>;
	getTreeItem(element: Pcap): vscode.TreeItem {
		return element;
	}
	getChildren(element?: Pcap): vscode.ProviderResult<Pcap[]> {
		if (element) {
			return [];
		}
		else {
			return this.filePcapStorage.concat(this.additionalPcapStorage);
		}
	}
}


function getPcaps(path: vscode.Uri): Pcap[] {
	let pcapFileNames = fs.readdirSync(path.fsPath).filter(file => {
		file.endsWith(".pcap");
	});
	return pcapFileNames.map(file => new Pcap(vscode.Uri.parse(file)));
}