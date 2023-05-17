import * as vscode from 'vscode';
import * as fs from 'fs';
import path = require('path');

export class PcapFile extends vscode.TreeItem {
	filepath: vscode.Uri;
	iconPath = vscode.ThemeIcon.File;
	contextValue = "pcapFile";

	constructor(filepath: vscode.Uri) {
		let filename = path.basename(filepath.fsPath);
		super(filename, vscode.TreeItemCollapsibleState.None);
		this.filepath = filepath;
	}

	refresh() { }

	remove(file: PcapFile) { }
}

export class PcapFolder extends vscode.TreeItem {
	filepath: vscode.Uri;
	pcapFiles: Map<string, PcapTreeItem>;
	iconPath = vscode.ThemeIcon.Folder;
	contextValue = "pcapFolder";

	constructor(filepath: vscode.Uri) {
		super(filepath.fsPath, vscode.TreeItemCollapsibleState.Collapsed);
		this.filepath = filepath;
		this.refresh();
	}

	/**
	 * Refresh the contents of the folder
	 */
	refresh() {
		this.pcapFiles = new Map();
		getPcaps(this.filepath).forEach(file => {
			this.pcapFiles.set(this.filepath.fsPath, file);
		});
	}

	remove(file: PcapFile) {
		this.pcapFiles.delete(file.filepath.fsPath);
	}
}

type PcapTreeItem = PcapFile | PcapFolder;

export class PcapProvider implements vscode.TreeDataProvider<PcapTreeItem> {
	pcapFiles: PcapTreeItem[];
	private _onDidChangeTreeData: vscode.EventEmitter<void | PcapFile | PcapFile[]> = new vscode.EventEmitter<void | PcapFile | PcapFile[]>();

	constructor() {
		// Initialize the storage
		this.pcapFiles = [];
		this.refresh();
	}

	/**
	 * Refresh the pcap files, found inside the folder
	 */
	refresh() {
		this.pcapFiles.forEach(file => file.refresh());
		this._onDidChangeTreeData.fire();
	}

	/**
	 * Add an aditional pcap file
	 * @param filepath the filepath of the additional file
	 */
	async addFile(filepath?: vscode.Uri) {
		if (filepath) {
			// check if the file is already added
			if (this.contains(filepath)) {
				vscode.window.showErrorMessage("File " + filepath.fsPath + "is already added to the PCAP files");
			}
			else {
				this.pcapFiles.push(new PcapFile(filepath));
			}
			return;
		}
		// else the filepath was not specified, so we need to ask the user
		let userResponse = await vscode.window.showOpenDialog({
			canSelectMany: true,
			title: "Please select the pcap files you wish to add",
			filters: { "Pcap files": ["pcap"] }
		})
		userResponse.forEach(file => {
			// check if the file is already added
			if (this.contains(file)) {
				vscode.window.showErrorMessage("File " + file.fsPath + "is already added to the PCAP files");
			}
			else {
				this.pcapFiles.push(new PcapFile(file));
			}
		})
		this.refresh();
	}

	async addFolder(filepath?: vscode.Uri) {
		if (filepath) {
			// check if the folder is already added
			if (this.contains(filepath)) {
				vscode.window.showErrorMessage("Folder " + filepath.fsPath + "is already added to the PCAP files");
			}
			else {
				this.pcapFiles.push(new PcapFolder(filepath));
			}
			return;
		}
		// else the filepath was not specified, so we need to ask the user
		let userResponse = await vscode.window.showOpenDialog({
			canSelectMany: false,
			title: "Please select the folder you wish to add",
			canSelectFiles: false,
			canSelectFolders: true
		})
		userResponse.forEach(file => {
			// check if the file is already added
			if (this.contains(file)) {
				vscode.window.showErrorMessage("Folder " + file.fsPath + "is already added to the PCAP files");
			}
			else {
				this.pcapFiles.push(new PcapFolder(file));
			}
		})
		this.refresh();
	}

	/**
	 * Checks if there is a file with that filepath in the PCAP storage
	 * @param filepath the path of the file
	 * @returns true, if the arrays contain such a filepath
	 */
	contains(filepath: vscode.Uri): boolean {
		return this.pcapFiles.find(pcap => pcap.filepath.fsPath === filepath.fsPath) !== undefined;
	}

	/**
	 * Removes files, based on the filepath
	 * @param filepath the file path of the file
	 */
	remove(filepath: PcapFile) {
		// Remove filepath if it is inside a folder
		this.pcapFiles.forEach(folder => folder.remove(filepath));
		// Remove filepath if it is a single file
		this.pcapFiles = this.pcapFiles.filter(file => file.filepath.fsPath !== filepath.filepath.fsPath);
		this.refresh();
	}

	readonly onDidChangeTreeData: vscode.Event<void | PcapTreeItem | PcapTreeItem[]> = this._onDidChangeTreeData.event;
	getTreeItem(element: PcapTreeItem): vscode.TreeItem {
		return element;
	}
	getChildren(element?: PcapTreeItem): vscode.ProviderResult<PcapTreeItem[]> {
		if (!element) {
			// return root if element is undefined
			return this.pcapFiles;
		}
		// else, check if it is a folder and return its contents
		if (element instanceof PcapFolder) {
			return Array.from((element as PcapFolder).pcapFiles.values());
		}
		else if (element instanceof PcapFile) {
			return [];
		}
		else {
			return [];
		}
	}
}


function getPcaps(rootPath: vscode.Uri): PcapFile[] {
	let pcapFileNames = fs.readdirSync(rootPath.fsPath).filter(file => {
		return file.endsWith(".pcap");
	});
	return pcapFileNames.map(file => new PcapFile(vscode.Uri.parse(path.join(rootPath.fsPath, file))));
}