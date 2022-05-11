use bitcoin::consensus::deserialize;
use bitcoin::hashes::hex::FromHex;
use bitcoin::util::address::{self, Address};
use bitcoin::{AddressType, Network, Script, Transaction, TxOut};

extern crate hex as hexfunc;

use std::collections::HashMap;

const NETWORK: Network = Network::Regtest;

#[derive(Debug, Eq, PartialEq)]
pub enum Heuristics {
    Multiscript,
    AddressReuse,
    RoundNumber,
}

#[derive(Debug)]
pub struct AnalysisResult {
    heuristic: Heuristics,
    result: bool,
    details: String,
}

fn decode_txn(hex_str: String) -> Transaction {
    //let tx_bytes = hexfunc::decode(hex_str).unwrap();
    let tx_bytes = Vec::from_hex(&hex_str).unwrap();
    let tx = deserialize(&tx_bytes).unwrap();
    //let tx = bitcoin::util::psbt::serialize::Deserialize::deserialize(&tx_bytes).unwrap();

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

pub fn check_address_reuse(txn: Transaction, prev_txns: HashMap<String, String>) -> AnalysisResult {
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

    let mut result: bool = false;

    for input_addr in input_addrs.iter() {
        for out_addr in output_addrs.iter() {
            if *input_addr == *out_addr {
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

pub fn check_round_number(tx_hex: String) -> AnalysisResult {
    //assuming payments have only 2 decimal places and only applies
    //to simple spend
    const SAT_PER_BTC: f64 = 100_000_000.0;
    let tx = decode_txn(tx_hex);

    let output_values: Vec<f64> = tx.output.iter().map(|out| out.value as f64 / SAT_PER_BTC).collect();
    
    let mut round_number:f64 = 0.0;
    for num in output_values {
        if (num * 10000.0).floor() as u64 % 10 == 0 {
            round_number = num
        }
    }

    let result = round_number != 0.0;

    return AnalysisResult {
        heuristic: Heuristics::RoundNumber,
        result,
        details: String::from("Found round number in outputs"),
    };
}

pub fn check_equaloutput_coinjoin(tx_hex: String) {
    let tx = decode_txn(tx_hex);
    // Assumption: we have a coinjoin transaction
    // check the output for equal payment amounts
    // return an analysis result
    const SAT_PER_BTC: f64 = 100_000_000.0;

    let output_values: Vec<f64> = tx.output.iter().map(|out| out.value as f64 / SAT_PER_BTC).collect();
    // let first_output_value = output_values.get(0).unwrap();
    for (index, &value) in output_values.iter().enumerate() {
        for (i, &v) in output_values.iter().enumerate() {
            if index == i {continue;}
            
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn test_check_multiscript() {
        let tx_hex = String::from("010000000001014c2686e762e0b260e7e146b5c15978c0b9366d80497b030390d91dc4ecf88f460100000000ffffffff02c4d600000000000017a914b607b1d108813cd10ae75e7b39305656ffea9523874b9b010000000000160014d86fe2f77cb04b0024a3783dc04b705b62c92f4502483045022100ce0ca2e3615c445d5fdedb4a289c7afcee303ef757c1539149a30a23b61f7c6102206a7d5a128224373213e778969d5a9428a52994f9e20ccac9d95e355e2230fd66012102b0747b954d5441f6df0b3daf2ca6bcbab7b6f3f42eda613789edd9d3a2dc40d800000000");
        let prev_tx_hex = String::from("01000000000101cb1c255d626dfbaea3557588725c779ebac6469e2c86a1d8647e6768751920100100000000ffffffff0259581000000000001600144c4afd82a9872b87836f0a4ee60250a0b857d0eaeb81020000000000160014ed7118d50af8e7e1f388d94972c23d5bb471c265024730440220199e11cffdc827ca91852416aa3263bdfadd95cd76c400f81e236a5cabcce18502202a4fe3cb84fe318d0c886e488d0b5ff099c6adfaa4bfce53a8d94bdb759dc1330121026c5f4446e09a7069f1b2bc35baf6a0ad9d7ed257fce5eac027a1c8466023fd5800000000");
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

    #[test]
    fn test_check_address_reuse() {
        let mut prev_txns = HashMap::new();
        prev_txns.insert(String::from("1c3ea699a24a17dd99533837e5a9cde84e0517033cf1deba18e9baca53c305d2"), String::from("010000000195d76b18853ab39712192be5f90bf350302eafa0c51067ca59af7bcb183b4025090000006b483045022100ef3c03a1e200a51da0df7117f0a7bcdef3c72b6c269be5123b404e5999b3a00002205e64a0392bd4dc2c7bc32f4a7978ddfbb440e0d9e504a71404fd8e05f88e3db001210256ba3dec93e8fda4485a8dea428d94aa968b509ec4ac430bf0de5f9027f988c8ffffffff0a09f006000000000017a91415adeb31f7415cbabafd07af8d90875d350655bc87989b58000000000017a914f384976b6e07df4c9bd7a212995ac4509e6c7d4787bc9b0c00000000001976a9149fdd37db4058fce4eeff3fca4bc5551590c9187d88ac5e163500000000001976a914bd28982b11113bfa720c3ff34ac9d09f8c6fb40f88ac806f4a0c000000001976a914e16873335e04467e02d8eb143f1302c685b8f31f88ac88e55a000000000017a9149907fae571a857e66ff83c4d70fa82e1286b06be876c796202000000001976a914981476e141da8d847b814b832e6402cd7338c6d188ac5896ec01000000001976a914c288197330741bc85587f4f00ee48c66e3be319488ac7f8446060000000017a9145d76ef27663a41a4a054d00886367e4a56e24e06874ffe9cc3000000001976a914e5fc50dec180de9a3c1c8f0309506321ae88def988ac00000000"));
        let curr_tx = decode_txn(String::from("0100000001d205c353cabae918badef13c0317054ee8cda9e537385399dd174aa299a63e1c030000006b483045022100af114bd31e351353f25b7260247ae1459f92697e50adef10ac2026182c6eceb2022023defe45fb7dfcdcca2e238b3566184fbf1ffe27e7c2e424df57e602f43e5c49012102c50332f6f13c902b397d1f84ad822ae5209bff1867042f466cd891024fdfaa8dffffffff02c0c62d00000000001976a9141323f3d1e32b79d8fe23d61019aff104884bff2a88ac57ac0600000000001976a914bd28982b11113bfa720c3ff34ac9d09f8c6fb40f88ac00000000"));
        println!("{:#?}", curr_tx);
        let analysis_result = check_address_reuse(curr_tx, prev_txns);

        assert_eq!(analysis_result.heuristic, Heuristics::AddressReuse);
        assert_eq!(analysis_result.result, true);
        assert_eq!(
            analysis_result.details,
            String::from("Input address reuse in outputs")
        )
    }
    #[test]
    fn test_check_round_number() {
        let tx_hex = String::from("0200000000010123c46091ab735545c6fa00a7db247b35cdc14d97639b9343598ede9d09ce26ea010000001716001442a9f77d14545b2a06ee2650bf39b32b0a0cb6cfffffffff02406603010000000017a914664fd79cf47e3d8525a13e167b68e5cfbb75382587111ff6260000000017a9140abc9d109b9b6bf6facc982783e9e3e12fa86cea870247304402207f1331495a9cf7658d336edb953eb0c138ca52769daebae52b76090066e92a9402202866dfd1edf4ac60c1d6d1cbf7f0e869a64d47cef8954ce7fd92eb6a641b7b08012102131da3e1de41815594d0e40e96c04d8b6b19f4f95af76f95c6cf3fdfa2563dc600000000");
        let analysis_result = check_round_number(tx_hex);
       
        assert_eq!(analysis_result.heuristic, Heuristics::RoundNumber);
        assert_eq!(analysis_result.result, true);
        assert_eq!(analysis_result.details, String::from("Found round number in outputs"));
    }
}
