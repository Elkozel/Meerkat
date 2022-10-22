use tower_lsp::lsp_types::Position;

use crate::rule::{Rule, Spanned, AST};

pub fn get_reference(
    ast: &AST,
    line: &u32,
    col: &usize,
    include_self: bool,
) -> Option<(Vec<Position>, String)> {
    let (rule, rule_span) = ast.rules.get(line)?; // Retrieve rule
    let (variable_name, variable_span) = get_variable_from_offset(rule, col)?; // Retrieve variable name from the offset

    let mut reference_list = vec![];
    ast.rules.iter().for_each(|(rule_line, (rule, rule_span))| { // go over each rule
        if !include_self && rule_line == line {
            return;
        }
        // get the header of the rule
        let (header, header_span) = &rule.header;
        // push the variables from the header, which have the name
        header.find_variables(&Some(variable_name.clone()), &mut reference_list);
    });
    Some(
        (reference_list
            .into_iter()
            .map(|(name, span)| Position::new(line.clone(), span.start as u32))
            .collect(), variable_name)
    )
}

fn get_variable_from_offset(rule: &Rule, col: &usize) -> Option<Spanned<String>> {
    let mut variables = vec![];
    rule.header.0.find_variables(&None, &mut variables);
    variables
        .into_iter()
        .find(|(var, var_span)| var_span.contains(col))
}
