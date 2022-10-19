use crate::rule::{AST, Spanned, NetworkAddress};

pub fn get_reference(ast: &AST, ident_offset: usize, include_self: bool) -> Vec<Spanned<String>> {
    let variable_name = get_variable_name(ast, &ident_offset);
    if let Some(variable_name) = variable_name {
        let mut reference_list = vec![];
        // Get all variables with the name
        get_variable_with_name(ast, &variable_name, &mut reference_list);
        if !include_self {
            return reference_list.into_iter().filter(|reference| !reference.1.contains(&ident_offset)).collect();
        }
        reference_list
    } else {
        vec![]
    }
}

fn get_variable_name(ast: &AST, ident_offset: &usize) -> Option<String> {
    let rule = ast
        .rules
        .iter()
        .find(|(_, span)| span.contains(ident_offset));
    if let Some((rule, _)) = rule {
        let source = &rule.header.0.source.0;
        let destination = &rule.header.0.destination.0;
        get_address_from_offset(source, ident_offset)
            .or(get_address_from_offset(destination, ident_offset))
    } else {
        return None;
    }
}

fn get_address_from_offset(address: &NetworkAddress, ident_offset: &usize) -> Option<String> {
    match address {
        NetworkAddress::IPGroup(group) => {
            let found = group.iter().find(|(_, span)| span.contains(ident_offset));
            match found {
                Some((rule, _)) => get_address_from_offset(rule, ident_offset),
                None => None,
            }
        }
        NetworkAddress::NegIP(ip) if ((ip.as_ref().1).contains(ident_offset)) => {
            get_address_from_offset(&ip.as_ref().0, ident_offset)
        }
        NetworkAddress::IPVariable((name, span)) if span.contains(ident_offset) => Some(name.to_owned()),
        _ => None,
    }
}

fn get_variable_with_name(ast: &AST, variable: &String, reference_list: &mut Vec<Spanned<String>>) {
    ast.rules.iter().for_each(|(rule, _)| {
        let source = &rule.header.0.source.0;
        let destination = &rule.header.0.destination.0;
        get_variable_from_address(source, variable, reference_list);
        get_variable_from_address(destination, variable, reference_list);
    })
}

fn get_variable_from_address(
    address: &NetworkAddress,
    variable: &String,
    reference_list: &mut Vec<Spanned<String>>,
) {
    match address {
        NetworkAddress::IPGroup(group) => group
            .iter()
            .for_each(|(ip, _)| get_variable_from_address(ip, variable, reference_list)),
        NetworkAddress::NegIP(address) => {
            get_variable_from_address(&address.as_ref().0, variable, reference_list)
        }
        NetworkAddress::IPVariable(var_name) => {
            if *variable == var_name.0 {
                reference_list.push(var_name.to_owned());
            }
        }
        _ => (),
    }
}
