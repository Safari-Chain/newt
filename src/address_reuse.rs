use std::collections::HashMap;
use std::fmt;

use bitcoin::psbt::PartiallySignedTransaction;
use bitcoin::util::address::Address;
use bitcoin::{psbt, Script, Transaction};

use crate::Heuristics;
use crate::{
    utils::{decode_txn, script_to_addr},
    AnalysisResult,
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

pub fn break_address_reuse_template(
    tx: &mut Transaction,
    new_addr: Address,
    analysis_result: &AnalysisResult,
) -> Result<Psbt> {
    //figure out the address that is being reused
    //change reused address with new address
    //build PSBT from Transaction
    let outputs = tx.output.clone();
    let mut new_outputs = Vec::new();

    //clear scriptsig in inputs
    //We are only doing this because we are using a test
    //transaction that has scriptsigs.
    for input in tx.input.iter_mut() {
        input.script_sig = Script::new();
    }

    for output in outputs.clone().iter_mut() {
        if analysis_result.change_addr.clone().unwrap()
            == script_to_addr(output.script_pubkey.clone())
        {
            output.script_pubkey = new_addr.script_pubkey();
        }
        new_outputs.push(output.clone());
    }

    tx.output = new_outputs;
    let psbt = Psbt::from_unsigned_tx(tx.clone())?;

    return Ok(psbt);
}

pub fn check_address_reuse(
    txn: &Transaction,
    prev_txns: &HashMap<String, String>,
) -> AnalysisResult {
    let mut input_addrs = Vec::new();

    for input in txn.input.iter() {
        //traverse the inputs
        //for every Outpoint aka (txid, vout), get transaction hex
        //in hash map, decode it. Get the output corresponding to the
        //vout from the outpoint. Extract the Address from this and
        //store it in an input address vector.
        let input_index = input.previous_output.vout;
        let tx_id = input.previous_output.txid.to_string();
        //Todo: handle case where hash map return none
        let tx_hex = prev_txns.get(&tx_id).unwrap();
        let decoded_tx = decode_txn(tx_hex.to_owned());
        let vout_output = decoded_tx.output[input_index as usize].clone();
        let input_addr = script_to_addr(vout_output.script_pubkey.clone());
        input_addrs.push(input_addr)
    }

    let output_addrs: Vec<Address> = txn
        .output
        .iter()
        .map(|tx_out| {
            return script_to_addr(tx_out.script_pubkey.clone());
        })
        .collect();

    println!("{:#?}", output_addrs);
    println!("{:#?}", input_addrs);
    let mut result: bool = false;
    let mut reuse_addr: Option<Address> = None;
    for input_addr in input_addrs.iter() {
        for out_addr in output_addrs.iter() {
            if *input_addr == *out_addr {
                result = true;
                reuse_addr = Some(input_addr.clone());
            }
        }
    }

    return AnalysisResult {
        heuristic: Heuristics::AddressReuse,
        result,
        details: String::from("Input address reuse in outputs"),
        template: true,
        change_addr: reuse_addr,
    };
}
