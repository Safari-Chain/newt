use std::fmt;

use bitcoin::psbt::PartiallySignedTransaction;
use bitcoin::util::address::{self, Address};
use bitcoin::{psbt, Script, Transaction, TxOut, Witness};

use crate::{
    utils::{get_address_type, parse_input_tx, script_to_addr},
    AnalysisResult, Heuristics,
};

type Psbt = PartiallySignedTransaction;
type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// PSBT error.
    Psbt(psbt::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {}

impl From<psbt::Error> for Error {
    fn from(e: psbt::Error) -> Error {
        Error::Psbt(e)
    }
}

pub fn break_multiscript_template(
    tx: &mut Transaction,
    change_addr: Option<Address>,
) -> Result<Psbt> {
    let change_addr_type = address::Address::address_type(&change_addr.clone().unwrap()).unwrap();
    let mut new_outputs = Vec::new();
    #[allow(unused_assignments, unused_variables)]
    let mut change_output_value: Option<u64> = None;
    #[allow(unused_assignments, unused_variables)]
    let mut payment_output: Option<TxOut> = None;

    //clear scriptsig in inputs
    //We are only doing this because we are using a test
    //transaction that has scriptsigs.
    for input in tx.input.iter_mut() {
        input.script_sig = Script::new();
        input.witness = Witness::default();
    }

    if change_addr.clone().unwrap() == script_to_addr(tx.output[0].script_pubkey.clone()) {
        change_output_value = Some(tx.output[0].value);
        payment_output = Some(tx.output[1].clone());
    } else {
        change_output_value = Some(tx.output[1].value);
        payment_output = Some(tx.output[0].clone());
    }

    for output in tx.output.iter_mut() {
        let output_addr_type =
            Address::address_type(&script_to_addr(output.script_pubkey.clone())).unwrap();
        if change_addr_type != output_addr_type {
            if output_addr_type.to_string() == "p2sh" {
                let script = Script::new().to_p2sh();
                let new_change_output = TxOut {
                    value: change_output_value.unwrap(),
                    script_pubkey: script,
                };
                new_outputs.push(new_change_output.clone());
                new_outputs.push(payment_output.clone().unwrap());
            }
            if output_addr_type.to_string() == "p2wsh" {
                let script = Script::new().to_v0_p2wsh();
                let new_change_output = TxOut {
                    value: change_output_value.unwrap(),
                    script_pubkey: script,
                };
                new_outputs.push(new_change_output.clone());
                new_outputs.push(payment_output.clone().unwrap());
            }
        }
    }

    tx.output = new_outputs;
    let psbt = Psbt::from_unsigned_tx(tx.clone())?;

    return Ok(psbt);
}

pub fn check_multi_script(txn: &Transaction, txn_in: String) -> AnalysisResult {
    let tx_in = txn.input.get(0).unwrap().clone();
    let vout_index = tx_in.previous_output.vout;

    let outputs = txn.output.clone();
    let addr_types = get_address_type(outputs.clone()).clone();
    let first_addr_type = *addr_types.get(0).unwrap();

    let output_script_types: Vec<String> = addr_types
        .into_iter()
        .map(|addr| addr.to_string())
        .collect();
    let input_script_type = parse_input_tx(txn_in, vout_index as usize).to_string();

    let mut compare_vouts = false;
    let mut compare_inp_out_addrtype = false;
    for output_script_type in output_script_types.iter() {
        if input_script_type == *output_script_type {
            compare_inp_out_addrtype = true;
        }
        if first_addr_type.to_string() != *output_script_type {
            compare_vouts = true;
        }
    }

    let result = compare_inp_out_addrtype && compare_vouts;

    let details = if result {
        "Multi-script"
    } else {
        "Single-script"
    };
    return AnalysisResult {
        heuristic: Heuristics::Multiscript,
        result,
        details: String::from(details),
        template: true,
        change_addr: None,
    };
}
