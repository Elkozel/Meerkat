import { ExtensionContext, StatusBarAlignment, StatusBarItem, ThemeColor, commands, window } from 'vscode';
import { getSuricataInfo, SuricataInfo } from './suricata';



// The status bar shows which suricata version was detected on the system (and if the build has rule analytics)
export class SuricataStatusBar {
	statusBarItem: StatusBarItem;
	suricataInfo: SuricataInfo;

	constructor() {
		this.statusBarItem = window.createStatusBarItem("Suricata status", StatusBarAlignment.Left, 10);
		commands.registerCommand("meerkat.status.refresh", () => this.refresh());
		this.refresh();
	}

	async refresh() {
		// Show the user information about the refresh
		this._statusLoading("$(loading) Searching for suricata","");
		// Refresh the suricata information we have
		this.suricataInfo = await getSuricataInfo();
		// If information is null, suricata is not installed
		if (this.suricataInfo == null) {
			// Tell that to the user
			const text = `$(circle-slash) Suricata not found`;
			const tooltip = `Suricata process was not found. Please make sure that suricata is inside the path variable. \n` +
				`Click to refresh`;
			this._statusError(text, tooltip);
		}
		// Else suricata is installed on the system
		else {
			// Present the info found to the user
			const text = `$(check) Suricata version ${this.suricataInfo.version}`;
			const tooltip = `Suricata version ${this.suricataInfo.version} found.\n` +
				`Running as a service: ${this.suricataInfo.asService ? "yes" : "no"} \n` +
				`Click to refresh`;
			this._statusNeutral(text, tooltip);
		}
		// Show the status bar
		this.statusBarItem.show();
	}

	/**
	 * Changes the status bar to show an error
	 * @param text The text to be displayed on the status bar
	 * @param tooltip The text to be displayed when the user hovers
	 */
	_statusError(text: string, tooltip: string) {
		this.statusBarItem.backgroundColor = new ThemeColor('statusBarItem.errorBackground');
		this.statusBarItem.text = text;
		this.statusBarItem.tooltip = tooltip;
	}

	/**
	 * Changes the status bar to appear neutral (with the theme of the editor)
	 * @param text The text to be displayed on the status bar
	 * @param tooltip The text to be displayed when the user hovers
	 */
	_statusNeutral(text: string, tooltip: string) {
		this.statusBarItem.backgroundColor = undefined;
		this.statusBarItem.text = text;
		this.statusBarItem.tooltip = tooltip;
	}

	/**
	 * Changes the status bar to appear as if it is loading
	 * @param text The text to be displayed on the status bar
	 * @param tooltip The text to be displayed when the user hovers
	 */
	_statusLoading(text: string, tooltip: string) {
		this.statusBarItem.backgroundColor = undefined;
		this.statusBarItem.text = text;
		this.statusBarItem.tooltip = tooltip;
	}
}