//! Provides the reference logic for the language server
//!
//! The reference logic is used to find matching variable names.
//! It is used by the editor for referencing and renaming.
use crate::rule::{Rule, Spanned, AST};

/// Get reference
pub fn get_reference(
    ast: &AST,
    line: &u32,
    col: &usize
) -> Option<Vec<(u32, Spanned<String>)>> {
    let (rule, _) = ast.rules.get(line)?; // Retrieve rule
    let (variable_name, _) = get_variable_from_offset(rule, col)?;
    let mut ret = vec![];
    ast.rules.iter().for_each(|(rule_line, (rule, _))| {// go over each rule
        // get the header of the rule
        let (header, _) = &rule.header;

        // push the variables from the header, which have the name
        let mut reference_list = vec![];
        header.find_address_variables(&Some(variable_name.clone()), &mut reference_list);
        header.find_port_variables(&Some(variable_name.clone()), &mut reference_list);

        // Push all references
        reference_list.into_iter().for_each(|var| {
            ret.push((rule_line.clone(), var));
        });
    });
    Some(ret)
}

/// Retrieve variable name from an offset
fn get_variable_from_offset(rule: &Rule, col: &usize) -> Option<Spanned<String>> {
    let mut variables = vec![];
    rule.header.0.find_address_variables(&None, &mut variables);
    rule.header.0.find_port_variables(&None, &mut variables);
    variables
        .into_iter()
        .find(|(_, var_span)| var_span.contains(col))
}
