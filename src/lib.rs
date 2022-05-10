extern crate hex as hexfunc;

use bitcoin::util::address::{self, Address};
use bitcoin::util::psbt::serialize::Deserialize;
use bitcoin::{AddressType, Network, Script, Transaction, TxOut};

const NETWORK: Network = Network::Regtest;

#[derive(Debug, Eq, PartialEq)]
pub enum Heuristics {
    Multiscript,
    AddressReuse,
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
    };
}

pub fn check_address_reuse(txn: Transaction, prev_txn_hex: String) -> AnalysisResult {
    //for every address used in the inputs i.e outpts of prev_txn
    //check if that address appears in the outputs of txn
    let prev_txn = decode_txn(prev_txn_hex);
    let prev_txn_outputs = prev_txn.output;
    let input_indexes: Vec<u32> = txn
        .input
        .iter()
        .map(|tx_in| tx_in.previous_output.vout)
        .collect();
    let mut input_addrs = Vec::new();
    let output_addrs: Vec<Address> = txn
        .output
        .iter()
        .map(|tx_out| {
            return script_to_addr(tx_out.script_pubkey.clone());
        })
        .collect();

    for index in input_indexes {
        //get the corresponding output in the previous transaction.
        let output_script = prev_txn_outputs[index as usize].script_pubkey.clone();

        //from this output, get the address
        let input_addr = script_to_addr(output_script);

        //store this address in vector
        input_addrs.push(input_addr);
    }

    let mut result: bool = false;

    for input_addr in input_addrs.iter() {
        for out_addr in output_addrs.iter() {
            if input_addr == out_addr {
                result = true;
            }
        }
    }

    return AnalysisResult {
        heuristic: Heuristics::AddressReuse,
        result,
        details: String::from("Input address reuse in outputs"),
    };
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn test_check_multiscript() {
        let tx_hex = String::from("010000000001014c2686e762e0b260e7e146b5c15978c0b9366d80497b030390d91dc4ecf88f460100000000ffffffff02c4d600000000000017a914b607b1d108813cd10ae75e7b39305656ffea9523874b9b010000000000160014d86fe2f77cb04b0024a3783dc04b705b62c92f4502483045022100ce0ca2e3615c445d5fdedb4a289c7afcee303ef757c1539149a30a23b61f7c6102206a7d5a128224373213e778969d5a9428a52994f9e20ccac9d95e355e2230fd66012102b0747b954d5441f6df0b3daf2ca6bcbab7b6f3f42eda613789edd9d3a2dc40d800000000");
        let prev_tx_hex = String::from("010000000001014c2686e762e0b260e7e146b5c15978c0b9366d80497b030390d91dc4ecf88f460100000000ffffffff02c4d600000000000017a914b607b1d108813cd10ae75e7b39305656ffea9523874b9b010000000000160014d86fe2f77cb04b0024a3783dc04b705b62c92f4502483045022100ce0ca2e3615c445d5fdedb4a289c7afcee303ef757c1539149a30a23b61f7c6102206a7d5a128224373213e778969d5a9428a52994f9e20ccac9d95e355e2230fd66012102b0747b954d5441f6df0b3daf2ca6bcbab7b6f3f42eda613789edd9d3a2dc40d80000000001000000000101cb1c255d626dfbaea3557588725c779ebac6469e2c86a1d8647e6768751920100100000000ffffffff0259581000000000001600144c4afd82a9872b87836f0a4ee60250a0b857d0eaeb81020000000000160014ed7118d50af8e7e1f388d94972c23d5bb471c265024730440220199e11cffdc827ca91852416aa3263bdfadd95cd76c400f81e236a5cabcce18502202a4fe3cb84fe318d0c886e488d0b5ff099c6adfaa4bfce53a8d94bdb759dc1330121026c5f4446e09a7069f1b2bc35baf6a0ad9d7ed257fce5eac027a1c8466023fd5800000000");
        let expected_result = AnalysisResult {
            heuristic: Heuristics::Multiscript,
            result: true,
            details: String::from("Multi-script"),
        };

        let tx = decode_txn(tx_hex.clone());
        let analysis_result = check_multi_script(tx, prev_tx_hex);

        assert_eq!(expected_result.heuristic, analysis_result.heuristic);
        assert_eq!(expected_result.result, analysis_result.result);
        assert_eq!(expected_result.details, analysis_result.details);
    }
}
