use bitcoin::consensus::deserialize;
use bitcoin::hashes::hex::FromHex;
use bitcoin::psbt::{self, PartiallySignedTransaction};
use bitcoin::util::address::{self, Address};
use bitcoin::{AddressType, Network, OutPoint, Script, Transaction, TxIn, TxOut, Txid, Witness};
use std::fmt;

extern crate hex as hexfunc;

use permute;
use std::collections::HashMap;

type Psbt = PartiallySignedTransaction;
type Result<T> = std::result::Result<T, Error>;

const NETWORK: Network = Network::Bitcoin;

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

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum Heuristics {
    Multiscript,
    AddressReuse,
    RoundNumber,
    Coinjoin,
    UnnecessaryInput,
    CommonInputOwnership,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TransactionType {
    SimpleSpend,
    Sweep,
    ConsolidationSpend,
    BatchSpend,
    CoinJoin,
    UnCategorized,
}

#[derive(Debug, PartialEq, Eq)]
pub struct AnalysisResult {
    heuristic: Heuristics,
    result: bool,
    details: String,
    template: bool,
    change_addr: Option<Address>,
}

pub fn decode_txn(hex_str: String) -> Transaction {
    let tx_bytes = Vec::from_hex(&hex_str).unwrap();
    let tx = deserialize(&tx_bytes).unwrap();
    //println!("transaction details: {:#?}", &tx);
    return tx;
}

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

fn is_sweep(tx: &Transaction) -> bool {
    let inputs = &tx.input;
    let outputs = &tx.output;

    return inputs.len() == 1 && outputs.len() == 1;
}

fn is_simple_spend(tx: &Transaction) -> bool {
    let inputs = &tx.input;
    let outputs = &tx.output;

    return inputs.len() >= 1 && outputs.len() == 2;
}

fn is_consolidation_spend(tx: &Transaction) -> bool {
    let inputs = &tx.input;
    let outputs = &tx.output;

    return inputs.len() > 1 && outputs.len() == 1;
}

fn is_batch_spend(tx: &Transaction) -> bool {
    let inputs = &tx.input;
    let outputs = &tx.output;

    return inputs.len() >= 1 && outputs.len() > 2;
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

pub fn check_round_number(tx: &Transaction) -> AnalysisResult {
    //assuming payments have only 2 decimal places and only applies
    //to simple spend
    const PRECISION: u64 = 5;
    let output_values: Vec<u64> = tx
        .output
        .iter()
        .map(|out| out.value )
        .collect();


    let mut check_freq_res = vec![true; output_values.len()];
    for (i, output_value) in output_values.iter().enumerate() {
        let mut prev_char = ' ';
        for (j, c) in output_value.to_string().chars().collect::<Vec<char>>().iter().enumerate() {
            if j != 0 && prev_char != *c {
                check_freq_res[i] = false;
            }
    
            prev_char = *c;
    
        }
    }

    let passed_freq_test = check_freq_res.iter().any(|x| *x);
    let mut result = false;

    if !passed_freq_test {
        for output_value in output_values.clone() {
            for i in 0..PRECISION {
                if  output_value %  10u64.pow(i as u32) != 0 {
                    result = true;
                }
            }
        
        }
    }
    

   
    
    
    return AnalysisResult {
        heuristic: Heuristics::RoundNumber,
        result: passed_freq_test || result,
        details: String::from("Found round number in outputs"),
        template: false,
        change_addr: None,
    };
}

pub fn check_equaloutput_coinjoin(tx: &Transaction) -> AnalysisResult {
    // Assumption: we have a coinjoin transaction
    // check the output for equal payment amounts
    // return an analysis result
    const SAT_PER_BTC: f64 = 100_000_000.0;

    let output_values: Vec<f64> = tx
        .output
        .iter()
        .map(|out| out.value as f64 / SAT_PER_BTC)
        .collect();
    let mut result = false;
    for (index, &value) in output_values.iter().enumerate() {
        for (i, &v) in output_values.iter().enumerate() {
            if index == i {
                continue;
            }

            if value == v {
                result = true;
                break;
            }
        }
    }

    return AnalysisResult {
        heuristic: Heuristics::Coinjoin,
        result,
        details: String::from("Found Equal Outputs Coinjoin"),
        template: false,
        change_addr: None,
    };
}

fn compute_unnecessary_inputs(tx: &Transaction, prev_txns: &Vec<TxOut>) -> Vec<bool> {
    const SAT_PER_BTC: f64 = 100_000_000.0;
    let outputs = tx.output.clone();
    let mut input_values = Vec::new();

    //Get input from prev txs outputs
    for v in prev_txns {
        input_values.push(v.value as f64 / SAT_PER_BTC);
    }

    let mut assert_unnecessary_inputs: Vec<bool> = vec![false; outputs.len()];

    if outputs.len() == 2 {
        let output_values: Vec<f64> = outputs
            .iter()
            .map(|out| out.value as f64 / SAT_PER_BTC)
            .collect();

        let permutated_inputs = permute::permute(input_values.clone());

        for (output_index, &output) in output_values.iter().enumerate() {
            for values in permutated_inputs.iter() {
                let mut sum_permuted_values: f64 = 0.0;
                for (value_index, &value) in values.iter().enumerate() {
                    sum_permuted_values += value;
                    if sum_permuted_values >= output {
                        if value_index < (values.len() - 1) {
                            assert_unnecessary_inputs[output_index] = true;
                            break;
                        }
                    }
                }
            }
        }
    }
    return assert_unnecessary_inputs;
}

pub fn check_unnecessary_input(
    tx: &Transaction,
    prev_txns: &HashMap<String, String>,
) -> AnalysisResult {
    // 1. check if total number of output is two
    // 2. get the value of each input and output in the transaction
    // 3. get the different permutations of the inputs
    // 4. For each output, check for unnecessary inputs using the permutation
    //compute <txid, txout>
    let mut outputs = Vec::new();

    for input in tx.input.clone() {
        let input_index = input.previous_output.vout;
        let tx_id = input.previous_output.txid.to_string();
        let tx_hex = prev_txns.get(&tx_id).unwrap();
        let decoded_tx = decode_txn(tx_hex.to_owned());
        let vout_output = decoded_tx.output[input_index as usize].clone();
        outputs.push(vout_output);
    }

    let result = !compute_unnecessary_inputs(tx, &outputs).iter().all(|&x| x);

    return AnalysisResult {
        heuristic: Heuristics::UnnecessaryInput,
        result,
        details: String::from("Found unnecessary inputs in transaction"),
        template: true,
        change_addr: None,
    };
}

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

pub fn categorize_tx(tx: &Transaction, is_coinjoin: bool) -> Vec<TransactionType> {
    let mut categories = Vec::new();

    if is_simple_spend(tx) {
        categories.push(TransactionType::SimpleSpend);
    }

    if is_sweep(tx) {
        categories.push(TransactionType::Sweep);
    }

    if is_consolidation_spend(tx) {
        categories.push(TransactionType::ConsolidationSpend)
    }

    if is_batch_spend(tx) {
        categories.push(TransactionType::BatchSpend);
    }

    if is_coinjoin {
        categories.push(TransactionType::CoinJoin);
    }

    if categories.is_empty() {
        categories.push(TransactionType::UnCategorized);
    }

    return categories;
}

pub fn transaction_analysis(
    tx_hex: String,
    is_coinjoin: bool,
    prev_txns: HashMap<String, String>,
) -> Vec<AnalysisResult> {
    let tx = decode_txn(tx_hex);
    let categories = categorize_tx(&tx, is_coinjoin);
    let mut analyses_result = Vec::new();

    for transaction_type in categories {
        if transaction_type == TransactionType::SimpleSpend {
            analyses_result.push(check_address_reuse(&tx, &prev_txns));
            analyses_result.push(check_common_input_ownership(&tx, &prev_txns));
            analyses_result.push(check_round_number(&tx));
            if prev_txns.len() == 1 {
                let txn_in = prev_txns.values().next().unwrap().to_owned();
                analyses_result.push(check_multi_script(&tx, txn_in));
            }

            if prev_txns.len() > 1 {
                analyses_result.push(check_unnecessary_input(&tx, &prev_txns));
            }
        }

        if transaction_type == TransactionType::Sweep {
            analyses_result.push(check_address_reuse(&tx, &prev_txns));
        }

        if transaction_type == TransactionType::ConsolidationSpend {
            analyses_result.push(check_address_reuse(&tx, &prev_txns));
            analyses_result.push(check_common_input_ownership(&tx, &prev_txns));
        }

        if transaction_type == TransactionType::BatchSpend {
            analyses_result.push(check_address_reuse(&tx, &prev_txns));
            analyses_result.push(check_common_input_ownership(&tx, &prev_txns));
        }

        if transaction_type == TransactionType::CoinJoin {
            analyses_result.push(check_equaloutput_coinjoin(&tx));
        }

        if transaction_type == TransactionType::UnCategorized {
            analyses_result.push(check_address_reuse(&tx, &prev_txns));
            analyses_result.push(check_common_input_ownership(&tx, &prev_txns));
            analyses_result.push(check_round_number(&tx));
            if prev_txns.len() == 1 {
                let txn_in = prev_txns.values().next().unwrap().to_owned();
                analyses_result.push(check_multi_script(&tx, txn_in));
            }
            analyses_result.push(check_unnecessary_input(&tx, &prev_txns));
        }
    }

    return analyses_result;
}

pub fn generate_transaction_template(
    prev_txns: Option<HashMap<String, String>>,
    utxo_set: Option<HashMap<(Txid, u64), String>>,
    tx_hex: String,
    change_addr: Option<Address>,
    analysis_results: Vec<AnalysisResult>,
) -> Option<PartiallySignedTransaction> {
    // 1. check if heuristic can be broken
    // 2. collect inputs based on heuristic and
    // generate template.
    // 2(a). collect 5 inputs - UTXO set, PSBT tx hex,
    // payment output address, analysis result list, wallet.
    // 2(b). check which analysis result returns true and
    // from which a template can be generated.
    //
    // Address-reuse, multiscript, unnecessary-inputs
    let mut tx = decode_txn(tx_hex);
    let mut prev_txs = prev_txns.unwrap();
    let utxos = utxo_set.unwrap();
    let mut passed_analysis = Vec::new();
    let mut transaction_template: Option<PartiallySignedTransaction> = None;

    for analysis_result in analysis_results {
        if analysis_result.result && analysis_result.template {
            passed_analysis.push(analysis_result);
        }
    }

    for analyzed in passed_analysis {
        if analyzed.heuristic == Heuristics::AddressReuse {
            match change_addr.clone() {
                Some(addr) => {
                    let result = break_address_reuse_template(&mut tx, addr, &analyzed).unwrap();
                    transaction_template = Some(result);
                }
                None => {
                    panic!("Expected Change Address");
                }
            }
        }
        if analyzed.heuristic == Heuristics::Multiscript {
            //break_multiscript_template(&)
            if analyzed.heuristic == Heuristics::Multiscript {
                let result = break_multiscript_template(&mut tx, change_addr).unwrap();
                transaction_template = Some(result);
                return transaction_template;
            }
            todo!();
        }

        if analyzed.heuristic == Heuristics::UnnecessaryInput {
            //break_unnecessary_input_template(&)
            let result = break_unnecessary_input_template(&mut prev_txs, &utxos, &mut tx).unwrap();
            transaction_template = Some(result);
            return transaction_template;
        }
    }

    return transaction_template;
}

pub fn break_unnecessary_input_template(
    prev_txns: &mut HashMap<String, String>,
    utxos: &HashMap<(Txid, u64), String>,
    tx: &mut Transaction,
) -> Result<Psbt> {
    // 1. grab the utxo set
    // 2. keep adding inputs till you have unnecessary inputs
    // for each of the outputs
    // 3. the inputs are selected at random
    // compute_unnecessary_inputs(tx, prev_txns)
    //build outputs and pass to the compute function.
    let mut outputs = Vec::new();
    
    for input in tx.input.iter() {
        let input_index = input.previous_output.vout;
        let tx_id = input.previous_output.txid.to_string();
        let tx_hex = prev_txns.get(&tx_id).unwrap();
        let decoded_tx = decode_txn(tx_hex.to_owned());
        let vout_output = decoded_tx.output[input_index as usize].clone();
        outputs.push(vout_output);
    }

    let mut utxo_iter = utxos.keys();

    loop {
        let result = compute_unnecessary_inputs(tx, &outputs).iter().all(|&x| x);

        //if result is false, add input to transaction from utxos set.
        //else break out of the loop and create psbt.
        if result {
            break;
        } else {
            //pick random utxo and add as input to tx
            let next_utxo = utxo_iter.next();

            match next_utxo {
                Some(key) => {
                    //let &val = utxos.get(key).unwrap();
                    //create input and add to transaction
                    let tx_in = TxIn {
                        previous_output: OutPoint {
                            txid: key.0,
                            vout: key.1 as u32,
                        },
                        script_sig: Script::new(),
                        sequence: 0xFFFFFFFF, // Ignore nSequence.
                        witness: Witness::default(),
                    };
                    tx.input.push(tx_in);
                    let utxo_output = decode_txn(utxos.get(key).unwrap().to_owned());
                    outputs.push(utxo_output.output.get(key.1 as usize).unwrap().clone());
                    prev_txns.insert(key.0.to_string(), utxos.get(key).unwrap().clone());
                }
                None => {
                    // return with an impossible message to user
                    let error = psbt::Error::NoMorePairs;
                    return Err(Error::Psbt(error));
                }
            }
        }
    }

    let psbt = Psbt::from_unsigned_tx(tx.clone())?;

    return Ok(psbt);
}

pub fn break_multiscript_template(
    tx: &mut Transaction,
    change_addr: Option<Address>,
) -> Result<Psbt> {
    let change_addr_type = address::Address::address_type(&change_addr.clone().unwrap()).unwrap();
    let mut new_outputs = Vec::new();
    let mut change_output_value: Option<u64> = None;
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

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use super::*;
    #[test]
    fn test_check_multiscript() {
        let tx_hex = String::from("010000000001014c2686e762e0b260e7e146b5c15978c0b9366d80497b030390d91dc4ecf88f460100000000ffffffff02c4d600000000000017a914b607b1d108813cd10ae75e7b39305656ffea9523874b9b010000000000160014d86fe2f77cb04b0024a3783dc04b705b62c92f4502483045022100ce0ca2e3615c445d5fdedb4a289c7afcee303ef757c1539149a30a23b61f7c6102206a7d5a128224373213e778969d5a9428a52994f9e20ccac9d95e355e2230fd66012102b0747b954d5441f6df0b3daf2ca6bcbab7b6f3f42eda613789edd9d3a2dc40d800000000");
        let tx = decode_txn(tx_hex);
        let prev_tx_hex = String::from("01000000000101cb1c255d626dfbaea3557588725c779ebac6469e2c86a1d8647e6768751920100100000000ffffffff0259581000000000001600144c4afd82a9872b87836f0a4ee60250a0b857d0eaeb81020000000000160014ed7118d50af8e7e1f388d94972c23d5bb471c265024730440220199e11cffdc827ca91852416aa3263bdfadd95cd76c400f81e236a5cabcce18502202a4fe3cb84fe318d0c886e488d0b5ff099c6adfaa4bfce53a8d94bdb759dc1330121026c5f4446e09a7069f1b2bc35baf6a0ad9d7ed257fce5eac027a1c8466023fd5800000000");
        let expected_result = AnalysisResult {
            heuristic: Heuristics::Multiscript,
            result: true,
            details: String::from("Multi-script"),
            template: false,
            change_addr: None,
        };
        let analysis_result = check_multi_script(&tx, prev_tx_hex);

        assert_eq!(expected_result.heuristic, analysis_result.heuristic);
        assert_eq!(expected_result.result, analysis_result.result);
        assert_eq!(expected_result.details, analysis_result.details);
        assert_eq!(expected_result.change_addr, None);
    }

    #[test]
    fn test_check_address_reuse() {
        let mut prev_txns = HashMap::new();
        prev_txns.insert(String::from("1c3ea699a24a17dd99533837e5a9cde84e0517033cf1deba18e9baca53c305d2"), String::from("010000000195d76b18853ab39712192be5f90bf350302eafa0c51067ca59af7bcb183b4025090000006b483045022100ef3c03a1e200a51da0df7117f0a7bcdef3c72b6c269be5123b404e5999b3a00002205e64a0392bd4dc2c7bc32f4a7978ddfbb440e0d9e504a71404fd8e05f88e3db001210256ba3dec93e8fda4485a8dea428d94aa968b509ec4ac430bf0de5f9027f988c8ffffffff0a09f006000000000017a91415adeb31f7415cbabafd07af8d90875d350655bc87989b58000000000017a914f384976b6e07df4c9bd7a212995ac4509e6c7d4787bc9b0c00000000001976a9149fdd37db4058fce4eeff3fca4bc5551590c9187d88ac5e163500000000001976a914bd28982b11113bfa720c3ff34ac9d09f8c6fb40f88ac806f4a0c000000001976a914e16873335e04467e02d8eb143f1302c685b8f31f88ac88e55a000000000017a9149907fae571a857e66ff83c4d70fa82e1286b06be876c796202000000001976a914981476e141da8d847b814b832e6402cd7338c6d188ac5896ec01000000001976a914c288197330741bc85587f4f00ee48c66e3be319488ac7f8446060000000017a9145d76ef27663a41a4a054d00886367e4a56e24e06874ffe9cc3000000001976a914e5fc50dec180de9a3c1c8f0309506321ae88def988ac00000000"));
        let curr_tx = String::from("0100000001d205c353cabae918badef13c0317054ee8cda9e537385399dd174aa299a63e1c030000006b483045022100af114bd31e351353f25b7260247ae1459f92697e50adef10ac2026182c6eceb2022023defe45fb7dfcdcca2e238b3566184fbf1ffe27e7c2e424df57e602f43e5c49012102c50332f6f13c902b397d1f84ad822ae5209bff1867042f466cd891024fdfaa8dffffffff02c0c62d00000000001976a9141323f3d1e32b79d8fe23d61019aff104884bff2a88ac57ac0600000000001976a914bd28982b11113bfa720c3ff34ac9d09f8c6fb40f88ac00000000");
        let curr_tx = decode_txn(curr_tx);
        let analysis_result = check_address_reuse(&curr_tx, &prev_txns);

        assert_eq!(analysis_result.heuristic, Heuristics::AddressReuse);
        assert!(analysis_result.result);
        assert_eq!(
            analysis_result.details,
            String::from("Input address reuse in outputs")
        )
    }
    #[test]
    fn test_check_round_number() {
        let tx_hex = String::from("0200000000010123c46091ab735545c6fa00a7db247b35cdc14d97639b9343598ede9d09ce26ea010000001716001442a9f77d14545b2a06ee2650bf39b32b0a0cb6cfffffffff02406603010000000017a914664fd79cf47e3d8525a13e167b68e5cfbb75382587111ff6260000000017a9140abc9d109b9b6bf6facc982783e9e3e12fa86cea870247304402207f1331495a9cf7658d336edb953eb0c138ca52769daebae52b76090066e92a9402202866dfd1edf4ac60c1d6d1cbf7f0e869a64d47cef8954ce7fd92eb6a641b7b08012102131da3e1de41815594d0e40e96c04d8b6b19f4f95af76f95c6cf3fdfa2563dc600000000");
        let tx = decode_txn(tx_hex);
        let analysis_result = check_round_number(&tx);

        assert_eq!(analysis_result.heuristic, Heuristics::RoundNumber);
        assert!(analysis_result.result);
        assert_eq!(
            analysis_result.details,
            String::from("Found round number in outputs")
        );
    }

    #[test]
    fn test_check_equaloutput_coinjoin() {
        let coinjoin_tx_hex = String::from("01000000000105f1ecbda8223b6cc28bd37f417f43fd8fa462dfede0e6385a18d5ffa430cbb70a0400000000ffffffff0c7b737926e5a21ceec19d20a630b80eb10e7e382efda4544e6ad1730f86b26d0300000000ffffffff679aafd80a2fc306a23d7c1a9bb0cf0d4d4c94d88f79243e8232d7b063e9ed760900000000ffffffffe30fa68d80a9533e843132ca2b8f6de641cbdb110d60e92a3add2ce96ac8af7b0100000000ffffffffae66da81e04dd25798394fb93161b9837e69034390a260df2d2959bc035309870300000000ffffffff0540420f000000000016001407539ac33dfcf782804085a13be4041a944cff1640420f00000000001600142de3d3be2b2cd8b00da7c9e46b645db3c136679d40420f00000000001600144668edd866cf4d9e1cd137c367b7c3f85158d21640420f00000000001600147f6f0faa9ad593e2ab53e3c889c69e19a36eef5d40420f0000000000160014e8abfe7ccf2048fbd7611b4b325557ac55708ece02483045022100c23d6bf44eb2589eca610268dc8f8f243dc8a6870d8ae1718c4f05210943d69a022064fd5ab81fb9dd831e3c4834787a8a8f06a5573f8f43b312ac8080877f8372850121023a21e68d0fa1c4ba8888f02ee40e8a9935d95a744c3d40d7f2d9f99a879be0f202483045022100dd779341477ef8581495bf937893c70890b0ebb3d02af796e57020fd64d1b33c0220268551e07d0fa2187d715a918a0784d9cc5cb0cdcae76125e48486af39b5ec59012103cccd7c5db03f9487f54c79fc379900238e2d55cd168585739a0423b308705c0202483045022100f782923ca6a3be8ddd5d6a3cd0a20df3d852b5edac5f5764c23156f509faa258022054d3b363a6a4582974e71ba6bd514236b5057b9fd4ca2894e0406e62fbeac9f1012102dd008796933c9d52f97a602338224b78ad1b1f82c62d56765869e11379817a9e02483045022100d7a255b4ff94d5f18851561f8ea79db3be6d076cd3e975e610f17e943484cb0e02205ee4e8f4aefe09bf40c34d8a9fe3a66b35148ab322a63ee0b34e168e3723f1c601210367b386171c9ccd683ef16b226f6ca4a8327f6f67027851013e05c6ffcf06531202473044022076cd0cc231afce90ce6ef1b716d273d215d37dc69aa1b6201af02f326f22f6cf02206a1ca8909a0649a7addf63f73c4c405abc7fc8f4b381828d78185bd83ecbdd590121023c899fd40d457014ecd3b1cedb10c48f545b81304e17bc0c9888756e105aa5a700000000");
        let tx = decode_txn(coinjoin_tx_hex);
        let analysis_result = check_equaloutput_coinjoin(&tx);

        assert_eq!(analysis_result.heuristic, Heuristics::Coinjoin);
        assert!(analysis_result.result);
        assert_eq!(
            analysis_result.details,
            String::from("Found Equal Outputs Coinjoin")
        );
    }

    #[test]
    fn test_check_unnecessary_inputs() {
        let mut prev_txns = HashMap::new();
        prev_txns.insert(String::from("4592bdfd2ed6dce6bbaa48ba7e38c13fa53f18ac057341db7ba2dafef2700106"), String::from("020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff050282000101ffffffff0200f2052a010000001600147a690d45185ebe54967f0735c48c48e86835932a0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000"));
        prev_txns.insert(String::from("19acb0de967acd5afffdb6ab92d4bd81beabfa7a3e1edd79b79ff657e3a1300a"), String::from("020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff050285000101ffffffff0200f2052a010000001600147a690d45185ebe54967f0735c48c48e86835932a0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000"));
        
        // prev_txns.insert(String::from("44141d713c616a49b48f6289d0a94c04498ce84db6106aa81078840a221d0bf5"), String::from("020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff050295000101ffffffff0200f2052a010000001600147a690d45185ebe54967f0735c48c48e86835932a0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000"));
        // prev_txns.insert(String::from("b9865cb28d3e17ae4779f6be743a0cd5943240077f8084404ca82c39b5b24bd1"), String::from("020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff050288000101ffffffff0200f2052a010000001600147a690d45185ebe54967f0735c48c48e86835932a0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000"));
        // prev_txns.insert(String::from("e20a44743301a90d009aa8a6dd32f95b39bf8cfe4d05ecc957657777e022bb79"), String::from("020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff05029c000101ffffffff0200f90295000000001600147a690d45185ebe54967f0735c48c48e86835932a0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000"));
        let curr_tx_hex = String::from("0200000002060170f2fedaa27bdb417305ac183fa53fc1387eba48aabbe6dcd62efdbd92450000000000ffffffff0a30a1e357f69fb779dd1e3e7afaabbe81bdd492abb6fdff5acd7a96deb0ac190000000000ffffffff020057d347010000001600140931cb36935b8d27010bb7892eb2501ea62af71000286bee0000000016001401e1010b82f73a6451eb03543a55b48df2cd372b00000000");
        let curr_tx = decode_txn(curr_tx_hex);
        let analysis_result = check_unnecessary_input(&curr_tx, &prev_txns);

        assert_eq!(analysis_result.heuristic, Heuristics::UnnecessaryInput);
        assert_eq!(analysis_result.result, true);
        assert_eq!(
            analysis_result.details,
            String::from("Found unnecessary inputs in transaction")
        );
    }

    #[test]
    fn test_common_input_ownership() {
        let mut prev_txns = HashMap::new();
        prev_txns.insert(String::from("0ab7cb30a4ffd5185a38e6e0eddf62a48ffd437f417fd38bc26c3b22a8bdecf1"), String::from("01000000000105431e152d6bbb8999195dded08eaa2ffc2ca0deef50826348b023a88f4a3db1480300000000ffffffffe23fe51cf5acff1f97a2bfbb927edfeb23b09d8c171f84922048d7cfc8534e910200000000ffffffff44fee26fc02dc0de5feb7f3c8b0d9f5f394635476dffdeb8eb2f2f08f33e30a30400000000ffffffff982d8ab9d9ac013b48a0de70998c5a7d3408ff22511f114acd84687bb0adf9a31600000000ffffffff38c096e1cf2a811d2648403e4a56ad25ce1080ab84a0acd9664d0b862b3461d08c00000000ffffffff0540420f00000000001600140da6910d6b26915be0805efabf3d50d8358e282340420f00000000001600140ebbbc724902c4ff5479c900c5b13db4b7cc11bf40420f000000000016001420e96bcc789179721fbbb319300b4ecd2941fbca40420f00000000001600143ba605de380d5a4fb5ce5fbf287c87be380d864440420f0000000000160014a998e07e4c768916fb80a1c50e124653b1ccbf4a02483045022100b63f9d50edef3f70eb06a60d4a3b22d28399595f5a6bd0c74d3b7b106f942fd802206cf3db9654c5fe1b8b93de2daddab712510667e258fee71303bfb80d872441440121035ad05ccb684a855fe181a0675650297ab79e7e7171cc03b92fabf7b8d4b3959402483045022100833b18451e722f6d0e53d05699945a6db095fa92f60300a0bfb5cb85cd9a2a3402207dbb0e13fafe7c056e23e811ae79d55e2fcae851ec576bb06277ff92d22c71c0012103f4b03d582cd5699248a80af269fcc645ecc26becc761842230cac3d8413c51720247304402204324ef1521394e17c42eb4959c758d77e8336156de7ae321fb56a54c8ee57f4a02205c37b555f38e9b0d7cff9198165710fd2d59d0fe4520890e5342ea59a79acf56012102e4c8ca32d3e6f4abfe004f658a67f9f300b9c2d116e1fa291247e548d0bc4fca024730440220268432a70b8606852a9eec07b8fb2e0740b2d2d844eae80716ccfdbcda7e5dcf022043f073329f2ac9a96c39d122e183d4b04893389f5dfb702b026008ae4c4e780a012102f8b45b34ba6d73dce62d415e13e61afa34253d3d921097b1542935e8a7bc6fe302473044022033deefc1f7b56c41c62ce27f76a6032de917559c0d5889520d548adbbaa40ed3022007bf86f5d2701fcce5ba26097dd8cdf6c49f2b80e09233047ec6afa7e163eccd01210363cbd09fadc91fae0c0a9fad9d18ceb1c7413dcb70969fe34f04f929a1f645ff00000000"));
        prev_txns.insert(String::from("6db2860f73d16a4e54a4fd2e387e0eb10eb830a6209dc1ee1ca2e52679737b0c"), String::from("0100000000010192b209f003d203f9e72756963b95b762b4cfb788d99fbde6b1501bb56fbcfd9e0000000000ffffffff090000000000000000426a4057de40bbc4e3661114c519797a86b605c961f0cec568fa7597f1641c7723bdf72522df8a645abb001d24d6b979478ca39816243bb9fb8e3cb79d6a715dbb176050c300000000000016001478fca19ac504d63def5e15fdfa1b00c06b3186e25530030000000000160014ccd968ddb97952054cb0b0104d13e628f7358d9557490f000000000016001409adf657d5afe006f1697ef94a126746657ab9c057490f00000000001600143def4094b95655be042bae91c7057dd3267d62bd57490f00000000001600145c5a8407eb9994bffce72ec8b5fc2db1a877337c57490f00000000001600149025bd5e7ff9065440dd657f697d365e7b4bb4ca57490f00000000001600149bc0f8169f359f8d44dc554c48fa07623f38351e57490f0000000000160014bdf1c85ad9148974b91188653e087e73f2d5ef4602473044022070ac382afc2bd5dfe636dbe2d047725978bd2d2fc37677acb26b750ededcaed80220228ec67071d293f9046aae41a0890d027dcf5ce0727c1a8f2a1d40b027183a7d012102e0ba24e121fb45163cc570eb1e2ff648e6accceb1de92c8826b22ffe0979dce200000000"));
        prev_txns.insert(String::from("76ede963b0d732823e24798fd8944c4d0dcfb09b1a7c3da206c32f0ad8af9a67"), String::from("010000000001031081d69b995f1f97bacdf50ed2b4c6ba4afce36273c4ba53814fe0c3a2921407340000006a473044022000cf525ba34c3cc5df7259bde4aba148e64259f49fbd2d73268e6ca0087eee9c02204f39cc780a3f520d5a1ce2dc58551af2b63a980d3fd4c5e86d185670e200952e012102c1eb8406911d5d72e5f234ae0725144f21398b3c9f9956fc72f1ca45b209151afffffffff7833b6d036c05c8a666391d493c4817d0b3e910074d42e0ea3cce618e706f410000000000ffffffff245d59e95e77114c237259e85a187ebae062bab36970b856f7b32df6784c51430100000000ffffffff110000000000000000426a4030b086f664c1467e9dba4573ddffd3309486dc3ac6f3d6a81135f3930cd4ff641897c32d06bdd10d7048c41b2343002af2a9c024d7b3b327a534cb8f5ee603f450c30000000000001600145286b9c60138b902727ff20ccf6548c11568f0fbb190050000000000160014753cfea5cc01d9579d73c100558837466d246b8228480f000000000016001423a652f02eb7af96d54fca33170e675cd1ab28df28480f000000000016001423bec0fb6bfb41aa8452e0ec12122cc1de293c4628480f000000000016001424eebb26fd4cb1775b8b7295f838740f4b207eda28480f000000000016001429a8d862a8f4170864d5de9f0e156f35442dc0dc28480f00000000001600143695d8823eb5f9ac8cb00dd59f4db7d286455f7928480f000000000016001459478018a428a6104d23578c5261dd160cb07b1d28480f000000000016001460137dfcad3cc2fdf5ffd90309dab2fde5349f2528480f0000000000160014663c3207bbf527e7dc1dd8d0053917dbf3bc65e228480f00000000001600146e8eff9c029006d26f1378e1855681d1b0b44f0e28480f000000000016001472540586c8a5f25869705b384b0ed85f9108094528480f000000000016001483e4d6828b634f694cfc49e3ed1c694f7781f37628480f0000000000160014a3be255bbbb996f582f136621d093bb290651c3928480f0000000000160014c3b0b0ec229082d1e549e6b44bf52fc5c783b42e28480f0000000000160014e48c746dcf75801c4cb32df41f1189aff60621f30002483045022100b9589ca25bad58f017661ebdd7bf53039b5b97bfa2fcf561ff1cf9f2bbbb44c202205e45772b268a33dcafec5d1d13c683a7b61f5b1aa54c2e8f6943bb620e5e476401210240daa3096f01381ce2804bc87cdd61f274ad9f16d6d49aa495dedd574c24b181024730440220101c2605be3d60a39682e16e50b10aabec39391a5f192af9dbcb1842a04f2ce902200ab7e9427b4d1839ee44f713d511ba8c47eb57a5ed6b99275004baf682539fc50121024e2252d10a0ada99b6c49c39735e0b8760c62e55b2a843a934813cfde97af64700000000"));
        prev_txns.insert(String::from("7bafc86ae92cdd3a2ae9600d11dbcb41e66d8f2bca3231843e53a9808da60fe3"), String::from("01000000000105a63ab0aa7b35a4100a70a4bd055a7f22f09e2208d4fbcbe2d7ea4135009357180400000000ffffffffa773ce7f00e9ccfb6cf7c0c2f8af5f57a2078e4ebbdd057634121e400fab5c250400000000ffffffff022a63a18a20b6df21da4dcab91c721eaf7bd7ce3b863acf8041c351f99476a50000000000ffffffff00bbeceb2ad18849f7f81f44a4e681e03091198d672a9d667cddbcd3fbbc73b00200000000ffffffffefec194c1cf5ee4d4405851a963710887da504463c04b1fd5b6d4257d7294bb70600000000ffffffff0540420f00000000001600142335a77e481b083ee6dc96c7b3a66df842bff08b40420f00000000001600145ff469b1b935f1b6770f4da64499942027216f0340420f00000000001600147496b5b19011ec9a184072fbd925b91a203dcbea40420f0000000000160014ab07696bf78c46f5364ea2b10cd19b6da7ef346e40420f0000000000160014bd0c488616a1ef28c76fda0aa8a9f100f3a9eca702473044022024d8641eca58c60016b610ca6beb6f4402abe33a8b8db944e18a523c2b0ff57f0220022da6730262c380d7441ea8585098dba76efbdcbee2b1fcf5b8d06139bf995e0121025f10beb134d2d6ea2b7d73bc739f3e71adef202ef2cb8218771712819bc2c7f20247304402203d3641686a30da1dab7d1b92cba7d2e6d2956a7a1062c312a73c490f7c1b4cf302207919eba6af8731b941e5a4bee459f487f8d493a6899e8ac6c54ff9d34b438bab012103341da0d8542dbc8e1de9b5dbf7dbd052790c891c339a790a2cae3d3b92a1e3ec02483045022100d254738816ff902db174fbf3338ad998cac0793ee5be031e123dd5f0c635f08c02206def61dec9d95ea390bd16c9e7049ff74d05d8cbab6634877f54a12594aa014d01210368dea4147ca31431a4c68a85661f4f08c222cb4b7d65c57c694476efbbadbbe802483045022100d5349c628e5228560167d588e4865a1080a978d495f038e7b00ec8e5a5a5dc6a02201cac2ef74dbccf51efb9bab9321ea07e9b222876f084c711d2ddb8f6df303ec701210226c076ffbecc196412c018b4ba6941f1b92da0a10d5e8841059f94f98819b4480247304402206317bd0bc8bcf6f741f6e8dc46e3ac3228d86d4a741a825f5a5fd7c0b412e71702203acb635484ed6c4deafb13a57a8e4efa1e9bd50dac5ce2e2d7c8152a683c2afc012103607be345b9e8bb3a6d94ad12bfac23af849e123184fc970afbda77cb32ee17bc00000000"));
        prev_txns.insert(String::from("87095303bc59292ddf60a2904303697e83b96131b94f399857d24de081da66ae"), String::from("010000000001019a84949654b7b83c75675ac3bd026380fbaf9d90391057f53b3043b6a10a635d0000000000ffffffff040000000000000000426a409f51dfdf7584cb3971cd17406537ea739a9a1ba4f57e5600f4e447210b5a6362eb6582204a61650ebe1fa83168d5dbc4720d4bc615bc3719b993f125e3df4ad0d535000000000000160014ac930a7c44a628cf909273b0d401a6bc61294eaf50c3000000000000160014240272cad422987ece94e5d3e7946a50be4f06101a680f00000000001600147b6b4d27cbb1f328b2d2393dd78fb3c1a97e85f7024730440220484180d13b6237a9b5313cb6f0f317953870926692eb5c18215dd71a67e24d0f02206d2807b48d8680705a56637dd5a653ed0170dcb6088fa4b5bab18eac7be1815701210376fbcd19eb2ccca98e781453c6c15651cb8f293c21de1b8dfdf68a0531990ee100000000"));
        let curr_tx_hex = String::from("01000000000105f1ecbda8223b6cc28bd37f417f43fd8fa462dfede0e6385a18d5ffa430cbb70a0400000000ffffffff0c7b737926e5a21ceec19d20a630b80eb10e7e382efda4544e6ad1730f86b26d0300000000ffffffff679aafd80a2fc306a23d7c1a9bb0cf0d4d4c94d88f79243e8232d7b063e9ed760900000000ffffffffe30fa68d80a9533e843132ca2b8f6de641cbdb110d60e92a3add2ce96ac8af7b0100000000ffffffffae66da81e04dd25798394fb93161b9837e69034390a260df2d2959bc035309870300000000ffffffff0540420f000000000016001407539ac33dfcf782804085a13be4041a944cff1640420f00000000001600142de3d3be2b2cd8b00da7c9e46b645db3c136679d40420f00000000001600144668edd866cf4d9e1cd137c367b7c3f85158d21640420f00000000001600147f6f0faa9ad593e2ab53e3c889c69e19a36eef5d40420f0000000000160014e8abfe7ccf2048fbd7611b4b325557ac55708ece02483045022100c23d6bf44eb2589eca610268dc8f8f243dc8a6870d8ae1718c4f05210943d69a022064fd5ab81fb9dd831e3c4834787a8a8f06a5573f8f43b312ac8080877f8372850121023a21e68d0fa1c4ba8888f02ee40e8a9935d95a744c3d40d7f2d9f99a879be0f202483045022100dd779341477ef8581495bf937893c70890b0ebb3d02af796e57020fd64d1b33c0220268551e07d0fa2187d715a918a0784d9cc5cb0cdcae76125e48486af39b5ec59012103cccd7c5db03f9487f54c79fc379900238e2d55cd168585739a0423b308705c0202483045022100f782923ca6a3be8ddd5d6a3cd0a20df3d852b5edac5f5764c23156f509faa258022054d3b363a6a4582974e71ba6bd514236b5057b9fd4ca2894e0406e62fbeac9f1012102dd008796933c9d52f97a602338224b78ad1b1f82c62d56765869e11379817a9e02483045022100d7a255b4ff94d5f18851561f8ea79db3be6d076cd3e975e610f17e943484cb0e02205ee4e8f4aefe09bf40c34d8a9fe3a66b35148ab322a63ee0b34e168e3723f1c601210367b386171c9ccd683ef16b226f6ca4a8327f6f67027851013e05c6ffcf06531202473044022076cd0cc231afce90ce6ef1b716d273d215d37dc69aa1b6201af02f326f22f6cf02206a1ca8909a0649a7addf63f73c4c405abc7fc8f4b381828d78185bd83ecbdd590121023c899fd40d457014ecd3b1cedb10c48f545b81304e17bc0c9888756e105aa5a700000000");
        let curr_tx = decode_txn(curr_tx_hex);
        let analysis_result = check_common_input_ownership(&curr_tx, &prev_txns);

        assert_eq!(analysis_result.heuristic, Heuristics::CommonInputOwnership);
        assert!(analysis_result.result);
        assert_eq!(
            analysis_result.details,
            String::from("Common Input Ownership found")
        );
    }

    #[test]
    fn test_categorize_tx_simple_spend() {
        let simple_spend_tx_hex = String::from("010000000001014c2686e762e0b260e7e146b5c15978c0b9366d80497b030390d91dc4ecf88f460100000000ffffffff02c4d600000000000017a914b607b1d108813cd10ae75e7b39305656ffea9523874b9b010000000000160014d86fe2f77cb04b0024a3783dc04b705b62c92f4502483045022100ce0ca2e3615c445d5fdedb4a289c7afcee303ef757c1539149a30a23b61f7c6102206a7d5a128224373213e778969d5a9428a52994f9e20ccac9d95e355e2230fd66012102b0747b954d5441f6df0b3daf2ca6bcbab7b6f3f42eda613789edd9d3a2dc40d800000000");
        let tx = decode_txn(simple_spend_tx_hex);

        let is_coinjoin = false;
        let transaction_types = categorize_tx(&tx, is_coinjoin);
        println!("transaction types: {:#?}", transaction_types);

        assert!(transaction_types.contains(&TransactionType::SimpleSpend));
    }

    #[test]
    fn test_categorize_tx_sweep() {
        let sweep_tx_hex = String::from("0100000000010175add4374c3a7fa81941babc87cc7160fa0f9dac3254683d97299d9ec1b81b5a0000000000ffffffff0176ebfa0200000000160014be989da04a33f036044495766cd9de8c2319155002483045022100d60a77d137f283ff1553d929bc3a869d48ebe22c491fa10ff727a9518ca126fb02207a4f8c5fb250538fcb3ec322a3ede082bc3e0271f88ce1acdaac493e7fea86ec012102429eff8ad6d244f88d43692b41386d85d0cd44d548380f61e65ad6d8e4613b8700000000");
        let tx = decode_txn(sweep_tx_hex);

        let is_coinjoin = false;
        let transaction_types = categorize_tx(&tx, is_coinjoin);
        println!("transaction types: {:#?}", transaction_types);

        assert!(transaction_types.contains(&TransactionType::Sweep));
    }

    #[test]
    fn test_categorize_tx_coinjoin() {
        let coinjoin_tx_hex = String::from("01000000000105f1ecbda8223b6cc28bd37f417f43fd8fa462dfede0e6385a18d5ffa430cbb70a0400000000ffffffff0c7b737926e5a21ceec19d20a630b80eb10e7e382efda4544e6ad1730f86b26d0300000000ffffffff679aafd80a2fc306a23d7c1a9bb0cf0d4d4c94d88f79243e8232d7b063e9ed760900000000ffffffffe30fa68d80a9533e843132ca2b8f6de641cbdb110d60e92a3add2ce96ac8af7b0100000000ffffffffae66da81e04dd25798394fb93161b9837e69034390a260df2d2959bc035309870300000000ffffffff0540420f000000000016001407539ac33dfcf782804085a13be4041a944cff1640420f00000000001600142de3d3be2b2cd8b00da7c9e46b645db3c136679d40420f00000000001600144668edd866cf4d9e1cd137c367b7c3f85158d21640420f00000000001600147f6f0faa9ad593e2ab53e3c889c69e19a36eef5d40420f0000000000160014e8abfe7ccf2048fbd7611b4b325557ac55708ece02483045022100c23d6bf44eb2589eca610268dc8f8f243dc8a6870d8ae1718c4f05210943d69a022064fd5ab81fb9dd831e3c4834787a8a8f06a5573f8f43b312ac8080877f8372850121023a21e68d0fa1c4ba8888f02ee40e8a9935d95a744c3d40d7f2d9f99a879be0f202483045022100dd779341477ef8581495bf937893c70890b0ebb3d02af796e57020fd64d1b33c0220268551e07d0fa2187d715a918a0784d9cc5cb0cdcae76125e48486af39b5ec59012103cccd7c5db03f9487f54c79fc379900238e2d55cd168585739a0423b308705c0202483045022100f782923ca6a3be8ddd5d6a3cd0a20df3d852b5edac5f5764c23156f509faa258022054d3b363a6a4582974e71ba6bd514236b5057b9fd4ca2894e0406e62fbeac9f1012102dd008796933c9d52f97a602338224b78ad1b1f82c62d56765869e11379817a9e02483045022100d7a255b4ff94d5f18851561f8ea79db3be6d076cd3e975e610f17e943484cb0e02205ee4e8f4aefe09bf40c34d8a9fe3a66b35148ab322a63ee0b34e168e3723f1c601210367b386171c9ccd683ef16b226f6ca4a8327f6f67027851013e05c6ffcf06531202473044022076cd0cc231afce90ce6ef1b716d273d215d37dc69aa1b6201af02f326f22f6cf02206a1ca8909a0649a7addf63f73c4c405abc7fc8f4b381828d78185bd83ecbdd590121023c899fd40d457014ecd3b1cedb10c48f545b81304e17bc0c9888756e105aa5a700000000");
        let tx = decode_txn(coinjoin_tx_hex);

        let is_coinjoin = true;
        let transaction_types = categorize_tx(&tx, is_coinjoin);
        println!("transaction types: {:#?}", transaction_types);

        assert!(transaction_types.contains(&TransactionType::CoinJoin));
    }

    #[test]
    fn test_transactions_analysis() {
        let mut prev_txns = HashMap::new();
        prev_txns.insert(String::from("1c3ea699a24a17dd99533837e5a9cde84e0517033cf1deba18e9baca53c305d2"), String::from("010000000195d76b18853ab39712192be5f90bf350302eafa0c51067ca59af7bcb183b4025090000006b483045022100ef3c03a1e200a51da0df7117f0a7bcdef3c72b6c269be5123b404e5999b3a00002205e64a0392bd4dc2c7bc32f4a7978ddfbb440e0d9e504a71404fd8e05f88e3db001210256ba3dec93e8fda4485a8dea428d94aa968b509ec4ac430bf0de5f9027f988c8ffffffff0a09f006000000000017a91415adeb31f7415cbabafd07af8d90875d350655bc87989b58000000000017a914f384976b6e07df4c9bd7a212995ac4509e6c7d4787bc9b0c00000000001976a9149fdd37db4058fce4eeff3fca4bc5551590c9187d88ac5e163500000000001976a914bd28982b11113bfa720c3ff34ac9d09f8c6fb40f88ac806f4a0c000000001976a914e16873335e04467e02d8eb143f1302c685b8f31f88ac88e55a000000000017a9149907fae571a857e66ff83c4d70fa82e1286b06be876c796202000000001976a914981476e141da8d847b814b832e6402cd7338c6d188ac5896ec01000000001976a914c288197330741bc85587f4f00ee48c66e3be319488ac7f8446060000000017a9145d76ef27663a41a4a054d00886367e4a56e24e06874ffe9cc3000000001976a914e5fc50dec180de9a3c1c8f0309506321ae88def988ac00000000"));
        let curr_tx_hex = String::from("0100000001d205c353cabae918badef13c0317054ee8cda9e537385399dd174aa299a63e1c030000006b483045022100af114bd31e351353f25b7260247ae1459f92697e50adef10ac2026182c6eceb2022023defe45fb7dfcdcca2e238b3566184fbf1ffe27e7c2e424df57e602f43e5c49012102c50332f6f13c902b397d1f84ad822ae5209bff1867042f466cd891024fdfaa8dffffffff02c0c62d00000000001976a9141323f3d1e32b79d8fe23d61019aff104884bff2a88ac57ac0600000000001976a914bd28982b11113bfa720c3ff34ac9d09f8c6fb40f88ac00000000");

        let analysis_result_list = transaction_analysis(curr_tx_hex, false, prev_txns);

        let expected_analysis_result = AnalysisResult {
            heuristic: Heuristics::UnnecessaryInput,
            result: true,
            details: String::from("Found unnecessary inputs in transaction"),
            template: true,
            change_addr: None,
        };
        println!("Analysis result list: {:#?}", analysis_result_list);

        assert!(analysis_result_list.contains(&expected_analysis_result));
    }

    #[test]
    fn test_break_address_reuse_template() {
        let curr_tx_hex = String::from("0100000001d205c353cabae918badef13c0317054ee8cda9e537385399dd174aa299a63e1c030000006b483045022100af114bd31e351353f25b7260247ae1459f92697e50adef10ac2026182c6eceb2022023defe45fb7dfcdcca2e238b3566184fbf1ffe27e7c2e424df57e602f43e5c49012102c50332f6f13c902b397d1f84ad822ae5209bff1867042f466cd891024fdfaa8dffffffff02c0c62d00000000001976a9141323f3d1e32b79d8fe23d61019aff104884bff2a88ac57ac0600000000001976a914bd28982b11113bfa720c3ff34ac9d09f8c6fb40f88ac00000000");
        let mut curr_tx = decode_txn(curr_tx_hex.clone());
        let mut prev_txns = HashMap::new();
        prev_txns.insert(String::from("1c3ea699a24a17dd99533837e5a9cde84e0517033cf1deba18e9baca53c305d2"), String::from("010000000195d76b18853ab39712192be5f90bf350302eafa0c51067ca59af7bcb183b4025090000006b483045022100ef3c03a1e200a51da0df7117f0a7bcdef3c72b6c269be5123b404e5999b3a00002205e64a0392bd4dc2c7bc32f4a7978ddfbb440e0d9e504a71404fd8e05f88e3db001210256ba3dec93e8fda4485a8dea428d94aa968b509ec4ac430bf0de5f9027f988c8ffffffff0a09f006000000000017a91415adeb31f7415cbabafd07af8d90875d350655bc87989b58000000000017a914f384976b6e07df4c9bd7a212995ac4509e6c7d4787bc9b0c00000000001976a9149fdd37db4058fce4eeff3fca4bc5551590c9187d88ac5e163500000000001976a914bd28982b11113bfa720c3ff34ac9d09f8c6fb40f88ac806f4a0c000000001976a914e16873335e04467e02d8eb143f1302c685b8f31f88ac88e55a000000000017a9149907fae571a857e66ff83c4d70fa82e1286b06be876c796202000000001976a914981476e141da8d847b814b832e6402cd7338c6d188ac5896ec01000000001976a914c288197330741bc85587f4f00ee48c66e3be319488ac7f8446060000000017a9145d76ef27663a41a4a054d00886367e4a56e24e06874ffe9cc3000000001976a914e5fc50dec180de9a3c1c8f0309506321ae88def988ac00000000"));
        let analysis_result_list = transaction_analysis(curr_tx_hex, false, prev_txns.clone());
        let new_addr = Address::from_str("bc1q8jnnr6d8wvtzymrngrzhu3p5hrff2cx9a6fshj").unwrap();
        let psbt_tx = break_address_reuse_template(
            &mut curr_tx,
            new_addr.clone(),
            analysis_result_list.get(0).unwrap(),
        )
        .unwrap();
        let tx = psbt_tx.extract_tx();
        let mut has_new_addr = false;
        for output in tx.output.iter() {
            let addr = script_to_addr(output.script_pubkey.clone());
            if addr == new_addr {
                has_new_addr = true;
            }
        }

        assert!(has_new_addr);
    }

    #[test]
    fn test_break_multiscript_template() {
        //tx: &mut Transaction, change_addr: Option<Address>
        let tx_hex = String::from("010000000001014c2686e762e0b260e7e146b5c15978c0b9366d80497b030390d91dc4ecf88f460100000000ffffffff02c4d600000000000017a914b607b1d108813cd10ae75e7b39305656ffea9523874b9b010000000000160014d86fe2f77cb04b0024a3783dc04b705b62c92f4502483045022100ce0ca2e3615c445d5fdedb4a289c7afcee303ef757c1539149a30a23b61f7c6102206a7d5a128224373213e778969d5a9428a52994f9e20ccac9d95e355e2230fd66012102b0747b954d5441f6df0b3daf2ca6bcbab7b6f3f42eda613789edd9d3a2dc40d800000000");
        let change_addr = Address::from_str("bc1q8jnnr6d8wvtzymrngrzhu3p5hrff2cx9a6fshj").unwrap();

        let mut tx = decode_txn(tx_hex);
        let psbt = break_multiscript_template(&mut tx, Some(change_addr)).unwrap();

        let extracted_tx = psbt.extract_tx();
        let prev_tx_hex = String::from("01000000000101cb1c255d626dfbaea3557588725c779ebac6469e2c86a1d8647e6768751920100100000000ffffffff0259581000000000001600144c4afd82a9872b87836f0a4ee60250a0b857d0eaeb81020000000000160014ed7118d50af8e7e1f388d94972c23d5bb471c265024730440220199e11cffdc827ca91852416aa3263bdfadd95cd76c400f81e236a5cabcce18502202a4fe3cb84fe318d0c886e488d0b5ff099c6adfaa4bfce53a8d94bdb759dc1330121026c5f4446e09a7069f1b2bc35baf6a0ad9d7ed257fce5eac027a1c8466023fd5800000000");
        let analysis_result = check_multi_script(&extracted_tx, prev_tx_hex);

        let expected_result = AnalysisResult {
            heuristic: Heuristics::Multiscript,
            result: false,
            details: String::from("Single-script"),
            template: false,
            change_addr: None,
        };

        assert_eq!(expected_result.heuristic, analysis_result.heuristic);
        assert_eq!(expected_result.result, analysis_result.result);
        assert_eq!(expected_result.details, analysis_result.details);
        assert_eq!(expected_result.change_addr, None);
    }

    #[test]
    fn test_break_unnecessary_input_template() {
        let tx_hex = String::from("0200000002060170f2fedaa27bdb417305ac183fa53fc1387eba48aabbe6dcd62efdbd92450000000000ffffffff0a30a1e357f69fb779dd1e3e7afaabbe81bdd492abb6fdff5acd7a96deb0ac190000000000ffffffff020057d347010000001600140931cb36935b8d27010bb7892eb2501ea62af71000286bee0000000016001401e1010b82f73a6451eb03543a55b48df2cd372b00000000");
        let mut tx = decode_txn(tx_hex);
        let mut prev_txns = HashMap::new();

        prev_txns.insert(String::from("4592bdfd2ed6dce6bbaa48ba7e38c13fa53f18ac057341db7ba2dafef2700106"), String::from("020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff050282000101ffffffff0200f2052a010000001600147a690d45185ebe54967f0735c48c48e86835932a0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000"));
        prev_txns.insert(String::from("19acb0de967acd5afffdb6ab92d4bd81beabfa7a3e1edd79b79ff657e3a1300a"), String::from("020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff050285000101ffffffff0200f2052a010000001600147a690d45185ebe54967f0735c48c48e86835932a0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000"));
        

        let mut utxos = HashMap::new();
        utxos.insert(
            (
                Txid::from_hex("3f1617ec41a0a99ec16cd867d725ecbd12643ae44a0d1ade9be0d72c3a5641c3")
                    .unwrap(),
                0,
            ),
            String::from("020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff050291000101ffffffff0200f2052a010000001600147a690d45185ebe54967f0735c48c48e86835932a0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000")
        );
        utxos.insert(
            (
                Txid::from_hex("a047fd97d88325f138cdaef98a417d71e04b48b422e65ed488bc43a2496f57ab")
                    .unwrap(),
                0,
            ),
            String::from("020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff050286000101ffffffff0200f2052a010000001600147a690d45185ebe54967f0735c48c48e86835932a0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000")
        );
        utxos.insert(
            (
                Txid::from_hex("32498041ab00bdfc4686a50dc56597aee43665a75031fc18d9cba303239c27a4")
                    .unwrap(),
                0,
            ),
            String::from("020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff05028b000101ffffffff0200f2052a010000001600147a690d45185ebe54967f0735c48c48e86835932a0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000")
        );
        utxos.insert(
            (
                Txid::from_hex("0a6ead87647ed0fc0ea804ff4b4565be9a0ad84790530f721dfe018b6f18c481")
                    .unwrap(),
                0,
            ),
            String::from("020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff050289000101ffffffff0200f2052a010000001600147a690d45185ebe54967f0735c48c48e86835932a0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000")
        );

        let psbt = break_unnecessary_input_template(&mut prev_txns, &utxos, &mut tx).unwrap();
        let extracted_tx = psbt.extract_tx();
        let analysis_result = check_unnecessary_input(&extracted_tx, &prev_txns);

        assert_eq!(analysis_result.heuristic, Heuristics::UnnecessaryInput);
        assert_eq!(analysis_result.result, false);
        assert_eq!(
            analysis_result.details,
            String::from("Found unnecessary inputs in transaction")
        );
    }
}
