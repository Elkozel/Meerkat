import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from "path";
import { executeSuricata } from './suricata';

/**
 * Extenssions for pcap files
 */
const PCAP_FILE_EXTENSSIONS = ["pcap", "pcapng", "cap"];
/**
 * Each item in the tree has a unique ID, which is incremented for each addition
 */
let ID = 0;
/**
 * Represent a pcap file into the tree view
 */
export class PcapFile extends vscode.TreeItem {
	iconPath = vscode.ThemeIcon.File;
	contextValue = "pcapFile";

	/**
	 * Construct a representation of a pcap file
	 * @param filepath the filepath of the pcap file
	 */
	constructor(filepath: vscode.Uri) {
		super(filepath, vscode.TreeItemCollapsibleState.None);
		this.id = (ID++).toString();
	}

	/**
	 * Open the pcap file in the editor
	 */
	async open() {
		try {
			await vscode.commands.executeCommand('vscode.open', this.resourceUri);
		}
		catch (err) {
			vscode.window.showErrorMessage(`Please make sure that an extenssion, which can render PCAP files is installed and activated (${err.toString()})`);
		}
	}

	/**
	 * A dummy function, does not do anything
	 */
	// eslint-disable-next-line @typescript-eslint/no-empty-function
	refresh() { }

	/**
	 * A dummy function, does not do anything
	 */
	// eslint-disable-next-line @typescript-eslint/no-empty-function
	remove(file: PcapFile) { }
}

/**
 * Represent a folder into the tree view
 */
export class PcapFolder extends vscode.TreeItem {
	pcapFiles: Map<string, PcapTreeItem>;
	iconPath = vscode.ThemeIcon.Folder;
	contextValue = "pcapFolder";

	constructor(filepath: vscode.Uri) {
		super(filepath, vscode.TreeItemCollapsibleState.Collapsed);
		this.id = (ID++).toString();
		this.refresh();
	}

	/**
	 * Refresh the contents of the folder to find new pcap files
	 */
	refresh() {
		this.pcapFiles = new Map();
		getPcaps(this.resourceUri).forEach(file => {
			this.pcapFiles.set(this.resourceUri.fsPath, file);
		});
	}

	/**
	 * Removes a pcap file from the folder. This does not delete the actual pcap file on the disk
	 * @param file the pcap file to be removed
	 */
	remove(file: PcapFile) {
		this.pcapFiles.delete(file.resourceUri.fsPath);
	}
}

type PcapTreeItem = PcapFile | PcapFolder;

export class PcapProvider implements vscode.TreeDataProvider<PcapTreeItem>, vscode.TreeDragAndDropController<PcapTreeItem> {
	pcapFiles: PcapTreeItem[];
	private _onDidChangeTreeData: vscode.EventEmitter<void | PcapFile | PcapFile[]> = new vscode.EventEmitter<void | PcapFile | PcapFile[]>();

	constructor(context: vscode.ExtensionContext) {
		// Register the tree view
		const view = vscode.window.createTreeView('pcaps', { treeDataProvider: this, showCollapseAll: true, dragAndDropController: this });
		context.subscriptions.push(view);
		// Register the comands for the tree view
		vscode.commands.registerCommand("meerkat.pcaps.addFile", (uri?: vscode.Uri) => this.addFile(uri));
		vscode.commands.registerCommand("meerkat.pcaps.execute", (file: PcapFile) => { executeSuricata(file.resourceUri); });
		vscode.commands.registerCommand("meerkat.pcaps.refresh", () => this.refresh());
		vscode.commands.registerCommand("meerkat.pcaps.remove", (file: PcapFile) => { this.remove(file); });
		vscode.commands.registerCommand("meerkat.pcaps.addFolder", (uri: vscode.Uri) => this.addFolder(uri));
		vscode.commands.registerCommand("meerkat.pcaps.previewPcap", (file: PcapFile) => file.open());
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
		const userResponse = await vscode.window.showOpenDialog({
			canSelectMany: true,
			title: "Please select the pcap files you wish to add",
			filters: {
				"Pcap files": PCAP_FILE_EXTENSSIONS,
				"any": ["*"]
			}
		});
		userResponse.forEach(file => {
			// check if the file is already added
			if (this.contains(file)) {
				vscode.window.showErrorMessage("File " + file.fsPath + "is already added to the PCAP files");
			}
			else {
				this.pcapFiles.push(new PcapFile(file));
			}
		});
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
		const userResponse = await vscode.window.showOpenDialog({
			canSelectMany: false,
			title: "Please select the folder you wish to add",
			canSelectFiles: false,
			canSelectFolders: true
		});
		userResponse.forEach(file => {
			// check if the file is already added
			if (this.contains(file)) {
				vscode.window.showErrorMessage("Folder " + file.fsPath + "is already added to the PCAP files");
			}
			else {
				this.pcapFiles.push(new PcapFolder(file));
			}
		});
		this.refresh();
	}

	/**
	 * Checks if there is a file with that filepath in the PCAP storage
	 * @param filepath the path of the file
	 * @returns true, if the arrays contain such a filepath
	 */
	contains(filepath: vscode.Uri): boolean {
		return this.pcapFiles.find(pcap => pcap.resourceUri.fsPath === filepath.fsPath) !== undefined;
	}

	/**
	 * Removes files, based on the filepath
	 * @param filepath the file path of the file
	 */
	remove(filepath: PcapFile) {
		// Remove filepath if it is inside a folder
		this.pcapFiles.forEach(folder => folder.remove(filepath));
		// Remove filepath if it is a single file
		this.pcapFiles = this.pcapFiles.filter(file => file.resourceUri.fsPath !== filepath.resourceUri.fsPath);
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


	/**
	 * Drag and drop controller
	 */
	dragMimeTypes = ['application/vnd.code.tree.pcaps', "text/uri-list"];
	dropMimeTypes = ['application/vnd.code.tree.pcaps', "text/uri-list"];
	handleDrag(source: readonly PcapTreeItem[], dataTransfer: vscode.DataTransfer, token: vscode.CancellationToken) {
		dataTransfer.set('application/vnd.code.tree.pcaps', new vscode.DataTransferItem(source));
		dataTransfer.set("text/uri-list", new vscode.DataTransferItem(source.map(item => item.resourceUri)));
	}
	handleDrop(target: PcapTreeItem, sources: vscode.DataTransfer, token: vscode.CancellationToken) {
		// Fetch all tree items
		const TreeItems = sources.get('application/vnd.code.tree.pcaps');
		// If there are tree items, add them to the target
		if (TreeItems) {
			const items: PcapTreeItem[] = TreeItems.value;

			items.forEach(treeItem => {
				// For now you can only add items to the root element (aka when target it undefined)
				if (target) {
					return;
				}
				else {
					this.pcapFiles.push(treeItem);
				}
			});
		}

		// Fetch all files
		const urlList = sources.get('text/uri-list');
		// If there are files, add them to the target
		if (urlList) {
			// First extract the string
			const urlListString: string = urlList.value;
			// The individual paths are all represented in a string, separated by `\r\n`. For example "Path\\1\r\nPath\\2"
			const items: vscode.Uri[] = urlListString.split("\r\n").map(uriString => vscode.Uri.parse("file:\\\\" + uriString));

			items.forEach(uriItem => {
				// For now you can only add items to the root element (aka when target it undefined)
				if (target) {
					return;
				}
				else {
					// Check if the Uri is pointing to a folder or a file
					if (fs.statSync(uriItem.fsPath).isDirectory()) {
						this.pcapFiles.push(new PcapFolder(uriItem));

					}
					else if (uriItem.fsPath.endsWith(".pcap")) {
						this.pcapFiles.push(new PcapFile(uriItem));
					} else {
						vscode.window.showErrorMessage(`File ${uriItem.fsPath} could not be added as it is not a pcap file or a folder`);
					}
				}
			});

		}
		this.refresh();
	}
}

/**
 * Searches for pcap files inside a folder. The search is basic and only looks at the file extenssion
 * @param rootPath the root path to look for pcaps
 * @returns the pcap files, which were found
 */
function getPcaps(rootPath: vscode.Uri): PcapFile[] {
	const pcapFileNames = fs.readdirSync(rootPath.fsPath).filter(file => {
		return PCAP_FILE_EXTENSSIONS.some(extenssion => file.endsWith(extenssion));
	});
	return pcapFileNames.map(file => new PcapFile(vscode.Uri.parse("file:/" + path.join(rootPath.fsPath, file))));
}