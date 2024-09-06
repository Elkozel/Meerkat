# Meerkat

Suricata Language Server

## How to install it
To install the language server:
```bash
git clone https://github.com/Elkozel/Meerkat.git
cd meerkat

cargo install
```

once installed, the binary is saved in `$HOME/.cargo/bin` and can be run with the following command:
```
meerkat
```

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


## Installation troubleshooting

### Linker 'cc' not found
If you get the following error:
```
error: linker `cc` not found
  |
  = note: No such file or directory (os error 2)

error: could not compile `quote` due to previous error
```
Try the following solution:
```
sudo apt install build-essential
```