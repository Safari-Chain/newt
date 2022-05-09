extern crate hex as hexfunc;

use bitcoin::util::address;
use bitcoin::util::psbt::serialize::Deserialize;
use bitcoin::{AddressType, Network, Script, Transaction, TxOut};

const NETWORK: Network = Network::Regtest;

#[derive(Debug, Eq, PartialEq)]
pub enum Heuristics {
    Multiscript,
}

#[derive(Debug)]
pub struct AnalysisResult {
    heuristic: Heuristics,
    result: bool,
    details: String,
}

/// Multi-script heuristic
/// (a) check if one of the outputs addresses type matches any of the input address type
/// (b) check if the address type of the outputs are different
///
// 1.) create function to collect and decode transaction hex(es) and
// convert it to a transaction struct
fn decode_txn(hex_str: String) -> Transaction {
    let tx_bytes = hexfunc::decode(hex_str).unwrap();

    let tx = bitcoin::blockdata::transaction::Transaction::deserialize(&tx_bytes).unwrap();
    println!("transaction details: {:#?}", &tx);
    return tx;
}

// 2. create function that converts scripts to addresses
fn script_to_addr(script: Script) -> address::Address {
    let addr = address::Address::from_script(&script, NETWORK).unwrap();
    addr
}

fn get_address_type(vouts: Vec<TxOut>) -> Vec<AddressType> {
    let address_type = vouts
        .into_iter()
        .map(|vout| {
            let addr = script_to_addr(vout.script_pubkey.clone());
            let addr_type = address::Address::address_type(&addr).unwrap();
            return addr_type;
        })
        .collect();
    return address_type;
}


fn parse_input_tx(txn_in: String, vout_index: usize) -> AddressType {
    let tx = decode_txn(txn_in);
    let outputs = tx.output;
    let addr_type = *get_address_type(outputs.clone()).get(vout_index).unwrap();
    return addr_type;
}

// 3. check for multi-script types using addresses
pub fn check_multi_script(txn: Transaction, txn_in: String) -> AnalysisResult {
    let tx_in = txn.input.get(0).unwrap().clone();
    let vout_index = tx_in.previous_output.vout;

    let outputs = txn.output;
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
        if first_addr_type.to_string() == *output_script_type {
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
    };
}


#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn test_check_multiscript() {
        let tx_hex_str = String::from("0200000001d79d2c25924044abb3692ed921dde899178db39897f3205074251f0e9f8e55710000000000ffffffff01f0e90f2401000000160014885ba915d7135763d23b3cbcb5a5486f9f6acb5900000000");
        let expected_result = AnalysisResult {
            heuristic: Heuristics::Multiscript,
            result: true,   
            details: String::from("Single-script"),
        };

        let tx = decode_txn(tx_hex_str.clone());
        //TODO: get hex for input transaction
        let analysis_result = check_multi_script(tx, tx_hex_str);

        assert_eq!(expected_result.heuristic, analysis_result.heuristic);
        assert_eq!(expected_result.result, analysis_result.result);
        assert_eq!(expected_result.details, analysis_result.details);
    }
}
