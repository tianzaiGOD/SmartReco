use std::{collections::HashMap, time::Duration};

use ethers::abi::AbiEncode;
use heimdall_common::{
    ether::signatures::{ResolvedError, ResolvedLog},
    io::{
        file::{short_path, write_file, write_lines_to_file},
        logging::{Logger, TraceFactory},
    },
    utils::strings::find_balanced_encapsulator,
};
use indicatif::ProgressBar;

use super::{
    super::{
        constants::{DECOMPILED_SOURCE_HEADER_SOL, STORAGE_ACCESS_REGEX},
        util::Function,
        DecompilerArgs,
    },
    postprocessers::solidity::postprocess,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct ABIToken {
    pub name: String,
    #[serde(rename = "internalType")]
    pub internal_type: String,
    #[serde(rename = "type")]
    pub type_: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct FunctionABI {
    #[serde(rename = "type")]
    pub type_: String,
    pub name: String,
    pub inputs: Vec<ABIToken>,
    pub outputs: Vec<ABIToken>,
    #[serde(rename = "stateMutability")]
    pub state_mutability: String,
    pub constant: bool,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct ErrorABI {
    #[serde(rename = "type")]
    pub type_: String,
    pub name: String,
    pub inputs: Vec<ABIToken>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct EventABI {
    #[serde(rename = "type")]
    pub type_: String,
    pub name: String,
    pub inputs: Vec<ABIToken>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum ABIStructure {
    Function(FunctionABI),
    Error(ErrorABI),
    Event(EventABI),
}

pub fn output(
    args: &DecompilerArgs,
    output_dir: String,
    functions: Vec<Function>,
    all_resolved_errors: HashMap<String, ResolvedError>,
    all_resolved_events: HashMap<String, ResolvedLog>,
    logger: &Logger,
    trace: &mut TraceFactory,
    trace_parent: u32,
) ->Vec<ABIStructure> {
    let mut functions = functions;

    let progress_bar = ProgressBar::new_spinner();
    progress_bar.enable_steady_tick(Duration::from_millis(100));
    progress_bar.set_style(logger.info_spinner());

    let abi_output_path = format!("{output_dir}/abi.json");
    let decompiled_output_path = format!("{output_dir}/decompiled.sol");

    // build the decompiled contract's ABI
    let mut abi: Vec<ABIStructure> = Vec::new();

    // build the ABI for each function
    for function in &functions {
        progress_bar.set_message(format!("writing ABI for '0x{}'", function.selector));

        // get the function's name parameters for both resolved and unresolved functions
        let (function_name, function_inputs, function_outputs) = match &function.resolved_function {
            Some(resolved_function) => {
                // get the function's name and parameters from the resolved function
                let mut inputs = Vec::new();
                let mut outputs = Vec::new();

                for (index, input) in resolved_function.inputs.iter().enumerate() {
                    inputs.push(ABIToken {
                        name: format!("arg{index}"),
                        internal_type: input.to_owned(),
                        type_: input.to_owned(),
                    });
                }

                match &function.returns {
                    Some(returns) => {
                        outputs.push(ABIToken {
                            name: "ret0".to_owned(),
                            internal_type: returns.to_owned(),
                            type_: returns.to_owned(),
                        });
                    }
                    None => {}
                }

                (format!("Unresolved_{}", function.selector), inputs, outputs)
            }
            None => {
                // if the function is unresolved, use the decompiler's potential types
                let mut inputs = Vec::new();
                let mut outputs = Vec::new();

                for (index, (_, (_, potential_types))) in
                function.arguments.clone().iter().enumerate()
                {
                    inputs.push(ABIToken {
                        name: format!("arg{index}"),
                        internal_type: potential_types[0].to_owned(),
                        type_: potential_types[0].to_owned(),
                    });
                }

                match &function.returns {
                    Some(returns) => {
                        outputs.push(ABIToken {
                            name: "ret0".to_owned(),
                            internal_type: returns.to_owned(),
                            type_: returns.to_owned(),
                        });
                    }
                    None => {}
                }

                (format!("Unresolved_{}", function.selector), inputs, outputs)
            }
        };

        // determine the state mutability of the function
        let state_mutability = match function.payable {
            true => "payable",
            false => match function.pure {
                true => "pure",
                false => match function.view {
                    true => "view",
                    false => "nonpayable",
                },
            },
        };

        let constant = state_mutability == "pure" && function_inputs.is_empty();

        // add the function to the ABI
        abi.push(ABIStructure::Function(FunctionABI {
            type_: "function".to_string(),
            name: function_name,
            inputs: function_inputs,
            outputs: function_outputs,
            state_mutability: state_mutability.to_string(),
            constant: constant,
        }));

        // write the function's custom errors
        for (error_selector, resolved_error) in &function.errors {
            progress_bar.set_message(format!("writing ABI for '0x{error_selector}'"));

            match resolved_error {
                Some(resolved_error) => {
                    let mut inputs = Vec::new();

                    for (index, input) in resolved_error.inputs.iter().enumerate() {
                        if !input.is_empty() {
                            inputs.push(ABIToken {
                                name: format!("arg{index}"),
                                internal_type: input.to_owned(),
                                type_: input.to_owned(),
                            });
                        }
                    }

                    // check if the error is already in the ABI
                    if abi.iter().any(|x| match x {
                        ABIStructure::Error(x) => x.name == resolved_error.name,
                        _ => false,
                    }) {
                        continue
                    }

                    abi.push(ABIStructure::Error(ErrorABI {
                        type_: "error".to_string(),
                        name: resolved_error.name.clone(),
                        inputs: inputs,
                    }));
                }
                None => {
                    // check if the error is already in the ABI
                    if abi.iter().any(|x| match x {
                        ABIStructure::Error(x) => {
                            x.name ==
                                format!(
                                    "CustomError_{}",
                                    &error_selector.encode_hex().replacen("0x", "", 1)
                                )
                        }
                        _ => false,
                    }) {
                        continue
                    }

                    abi.push(ABIStructure::Error(ErrorABI {
                        type_: "error".to_string(),
                        name: format!(
                            "CustomError_{}",
                            &error_selector.encode_hex().replacen("0x", "", 1)
                        ),
                        inputs: Vec::new(),
                    }));
                }
            }
        }

        // write the function's events
        for (event_selector, (resolved_event, _)) in &function.events {
            progress_bar.set_message(format!("writing ABI for '0x{event_selector}'"));

            match resolved_event {
                Some(resolved_event) => {
                    let mut inputs = Vec::new();

                    for (index, input) in resolved_event.inputs.iter().enumerate() {
                        if !input.is_empty() {
                            inputs.push(ABIToken {
                                name: format!("arg{index}"),
                                internal_type: input.to_owned(),
                                type_: input.to_owned(),
                            });
                        }
                    }

                    // check if the event is already in the ABI
                    if abi.iter().any(|x| match x {
                        ABIStructure::Event(x) => x.name == resolved_event.name,
                        _ => false,
                    }) {
                        continue
                    }

                    abi.push(ABIStructure::Event(EventABI {
                        type_: "event".to_string(),
                        name: resolved_event.name.clone(),
                        inputs: inputs,
                    }));
                }
                None => {
                    // check if the event is already in the ABI
                    if abi.iter().any(|x| match x {
                        ABIStructure::Event(x) => {
                            x.name ==
                                format!(
                                    "Event_{}",
                                    &event_selector.encode_hex().replacen("0x", "", 1)[0..8]
                                )
                        }
                        _ => false,
                    }) {
                        continue
                    }

                    abi.push(ABIStructure::Event(EventABI {
                        type_: "event".to_string(),
                        name: format!(
                            "Event_{}",
                            &event_selector.encode_hex().replacen("0x", "", 1)[0..8]
                        ),
                        inputs: Vec::new(),
                    }));
                }
            }
        }
    }

    return abi;
}
