use crate::rule::{Rule, Spanned, AST};

pub fn get_reference(
    ast: &AST,
    line: &u32,
    col: &usize,
    include_self: bool,
) -> Option<Vec<(u32, Spanned<String>)>> {
    let (rule, _) = ast.rules.get(line)?; // Retrieve rule
    let (variable_name, _) = get_variable_from_offset(rule, col)?; // Retrieve variable name from the offset

    let mut reference_list = vec![];
    ast.rules.iter().for_each(|(rule_line, (rule, _))| {
        // go over each rule
        // if !include_self && rule_line == line {
        //     return;
        // }
        // get the header of the rule
        let (header, _) = &rule.header;
        // push the variables from the header, which have the name
        header.find_address_variables(&Some(variable_name.clone()), &mut reference_list);
    });
    Some(
        reference_list
            .into_iter()
            .map(|reference| (line.clone(), reference))
            .collect(),
    )
}

fn get_variable_from_offset(rule: &Rule, col: &usize) -> Option<Spanned<String>> {
    let mut variables = vec![];
    rule.header.0.find_address_variables(&None, &mut variables);
    variables
        .into_iter()
        .find(|(_, var_span)| var_span.contains(col))
}
