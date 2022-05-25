use std::collections::HashMap;

use bitcoin::Transaction;

use crate::{utils::{decode_txn, script_to_addr}, AnalysisResult, Heuristics};

pub fn check_common_input_ownership(
    txn: &Transaction,
    prev_txns: &HashMap<String, String>,
) -> AnalysisResult {
    //for every input in current transaction
    //get address associate to that input using txid and associated tx
    let mut input_addrs = Vec::new();
    let mut result = false;

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

    let first = &input_addrs[0];
    for address in input_addrs.iter() {
        if *first != *address {
            result = true;
        }
    }

    return AnalysisResult {
        heuristic: Heuristics::CommonInputOwnership,
        result,
        details: String::from("Common Input Ownership found"),
        template: false,
        change_addr: None,
    };
}
