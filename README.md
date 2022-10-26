# Meerkat

Suricata/Snort formatter extension for VS Code

Meerkat provides the following features:
- Syntax highlighting via semantic tokens
- Signature formatting
- Hover information
- Variable references/renaiming
- Code completion (partially)
- Rule performance statistics (TODO)
- Code snipplets (TOOD)
- Rule linting (TOOD)

## Structure
Meerkat consists of three parts:
- Parser: powered by chumsky, the signature parser promises high-speed and high-reliability signature parser.
- Server logic: once a rule is parsed, it is analyzed to provide useful debugging and linting information to the user.
- Language server: the tower framework is used to create a language server, which can be used by any text editor, which [supports the LSP](https://microsoft.github.io/language-server-protocol/implementors/tools/).

## How to install it

### Linux/Mac
Install cargo, if you have not done already:
```bash
npm run install-rust
```
*You will be propted to accept the default configuration*

Install all dependencies for the project:
```bash
npm install
```

Pack the extenssion:
```bash
# install the vs code packing tool
sudo npm install -g vsce
# package the extenssion
vsce package
```
*The script will also move the meerkat language server to the local bin folder (I am still looking for a better way)*

At the end you should have a file named meerkat.vsix, which can be opened by VSCode

### Windows
WIP

## Suricata signatures

### Docs
The [suricata documentation](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html#rule-options) was used for a deeper understanding of the sturcture and function of suricata rules

### Grammar
The following grammar was used to implement a praser for the rules:
```
<Rule> ::= <action> " " <header> " " "(" <options> ")"
<action> ::= "alert" | "pass" | "drop" | "reject" | "rejectsrc" | "rejectdst" | "rejectboth"
<header> ::= <protocol> " " <IPAddress> " " <port> " " <direction> " " <IPAddress> " " <port>

<protocol> ::= [a-z]+

/* Handling IP Addresses */
<IPAddress> ::= <IPRange> | <NegatedIP> | <IPGroup> | <variable> | "any"

<IPGroup> ::= "[" <IPAddress> ("," <IPAddress>)* "]"
/* any number containing 1 to 3 digits */
<IPQuart> ::= ([0-9] [0-9]? [0-9]?)
/* any 4 numbers separated by dots*/
<IP> ::= <IPQuart> "." <IPQuart> "." <IPQuart> "." <IPQuart>
/* CIDR */
<IPRange> ::= <IP> "\\" ([0-9] [0-9]?) 
<NegatedIP> ::= "!" (<IP> | <IPRange> | <IPGroup> | <variable>)
<variable> ::= "$" ([a-z] [A-Z] "-" "_")+

/* Handling ports */
<port> ::= <portNumber> | <portGroup> | "any"

<portNumber> ::= ([0-9] [0-9]? [0-9]? [0-9]? [0-9]?)
<portRange> ::= <portNumber> ":" <portNumber>?
<negatedPort> ::= "!" (<portNumber> | <portRange> | <portGroup>)
<portGroup> ::= "[" <port> ("," <port>)* "]"

/* Directions */
<direction> ::= "->" | "<>" | "<-"


<options> ::= <option>+
<option> ::= <keyword> ":" <settings> ";" | <keyword> ";"
<keyword> ::= ([a-z] [A-Z] "_" "-")+
<settings> ::= ([a-z] [A-Z] "_" "-")+ | (<settings> ("," <settings>)+)
```

## I want to contribute
You can easily contribute by reporting issues to the Git page of the project

If you want to contribute by writing code, the rust docs for the project is a perfect location to start at, just run:
```bash
cargo doc --open
```