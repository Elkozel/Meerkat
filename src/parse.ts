import * as vscode from 'vscode';

class Header {
    protocol: string;
    direction: string;
    source: string;
    sourcePort: string;
    destination: string;
    destinationPort: string;

    constructor(protocol: string, direction: string, source: string, sourcePort: string, destination: string, destinationPort: string) {
        this.protocol = protocol;
        this.direction = direction;
        this.source = source;
        this.sourcePort = sourcePort;
        this.destination = destination;
        this.destinationPort = destinationPort;
    }

    toRule(): string {
        return `${this.protocol} ${this.source} ${this.sourcePort} ${this.direction} ${this.destination} ${this.destinationPort}`;
    }
}

class Option {
    keyword: string;
    setting?: string;

    constructor(keyword: string, setting?: string) {
        this.keyword = keyword;
        this.setting = setting;
    }

    toRule(): string {
        let spaceAfterSemicolomnInOption = vscode.workspace.getConfiguration().get("suricata.formatSpaceAfterSemicolomnInOption") ? ' ' : '';
        return this.setting ? `${this.keyword}:${spaceAfterSemicolomnInOption}${this.setting}` : `${this.keyword}`;
    }
}

class Rule {
    action: string;
    header: Header;
    options: Option[];

    constructor(action: string, header: Header, options: Option[]) {
        this.action = action;
        this.header = header;
        this.options = options;
    }

    toRule(): string {
        let spaceAfterOption = vscode.workspace.getConfiguration().get("suricata.formatSpaceAfterOption") ? ' ' : '';
        let spaceAfterLastOption = vscode.workspace.getConfiguration().get("suricata.formatSpaceAfterLastOption") ? ' ' : '';
        return `${this.action} ${this.header.toRule()} (${this.options.map(op => op.toRule()).join(`;${spaceAfterOption}`)};${spaceAfterLastOption})`;
    }
}

export function parseRule(input: string): Rule {
    let action = parseAction(input);
    let header = parseHeader(input);
    let options = parseOptions(input);

    return new Rule(action, header, options);
}

function parseAction(input: string): string {
    let firstSpace = input.trim().indexOf(" ");
    if (firstSpace <= 0)
        throw new Error("Invalid rule: no action found!");
    return input.substring(0, firstSpace).trim();
}

function parseHeader(input: string): Header {
    const IP = /[0-9]{1,3}(.[0-9]{1,3}){3} /;
    const CIDR = /[0-9]{1,3}(.[0-9]{1,3}){3}\/[0-9]{1,2} /;
    const grouping = /\[[^\[]*\]/;

    input = input.trim();
    // Grab only header of rule
    let firstSpace = input.indexOf(" ");
    let secondSpace = input.indexOf(" ", firstSpace + 1);
    let optionsStart = input.indexOf("(");
    if (optionsStart === null)
        throw new Error("Invalid rule: no action found!");

    let protocol = input.substring(firstSpace, secondSpace).trim();
    input = input.substring(secondSpace, optionsStart).trim();

    // Check for direction
    var source, destination;
    var direction;
    if (input.indexOf("->") > 0) {
        [source, destination] = input.split("->");
        direction = "->";
    }
    else if (input.indexOf("<>") > 0) {
        [source, destination] = input.split("<>");
        direction = "<>";
    }
    else
        throw new Error("Invalid rule: no direction found");

    // Create rule
    let [sourceIP, sourcePort] = source.trim().split(" ");
    let [destinationIP, destinationPort] = destination.trim().split(" ");

    return new Header(protocol, direction, sourceIP.trim(), sourcePort.trim(), destinationIP.trim(), destinationPort.trim());
}


interface Option {
    keyword: string,
    setting?: string
}
function parseOptions(input: string): Option[] {
    let optionsRegex = /[^\\]\(.+[^\\]\)/g;
    let optionsRaw = input.match(optionsRegex);
    if (optionsRaw === null)
        throw new Error("Invalid rule: no options found!");
    let options = optionsRaw[0].trim().substring(1, optionsRaw[0].length - 2).trim().split(";"); // get all options
    options.pop(); // remove last element

    return options.map<Option>(op => {
        if (op.indexOf(":") > 0) { // the keyword is of type <keyword>: <settings>;
            let split = op.indexOf(":");
            let keyword = op.substring(0, split);
            let settings = op.substring(split + 1);
            return new Option(keyword.trim(), settings.trim());
        }
        // else it is a Modifier Keywords (<keyword>;)
        return new Option(op.trim());
    })
}