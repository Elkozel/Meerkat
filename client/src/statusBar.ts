import { StatusBarAlignment, StatusBarItem, ThemeColor, window } from 'vscode';
import { getSuricataInfo, SuricataInfo } from './suricata';
import { Command } from 'vscode-languageclient';



// The status bar shows which suricata version was detected on the system (and if the build has rule analytics)
export class SuricataStatusBar {
	statusBarItem: StatusBarItem;
	suricataInfo: SuricataInfo;

	constructor() {
		this.statusBarItem = window.createStatusBarItem(StatusBarAlignment.Left, 10);
		this.statusBarItem.command = "meerkat.status.refresh";
		this.refresh();
	}

	async refresh() {
		this.suricataInfo = await getSuricataInfo();
		if (this.suricataInfo == null) {
			this.statusBarItem.backgroundColor = new ThemeColor('statusBarItem.errorBackground');
			this.statusBarItem.text = "$(circle-slash) Suricata not found";
			this.statusBarItem.tooltip = "Suricata process was not found inside the Path variable. \n Click to refresh";
		}
		else {
			this.statusBarItem.backgroundColor = undefined;
			this.statusBarItem.text = `$(check) Suricata version ${this.suricataInfo.version}`;
			this.statusBarItem.tooltip = `Suricata version ${this.suricataInfo.version} found. \n Running as a service: ${this.suricataInfo.asService ? "yes" : "no"} \n Click to refresh`;
		}
		this.statusBarItem.show();
	}
}