use std::collections::HashMap;
use std::fmt;

use crate::{utils::decode_txn, Heuristics};

use bitcoin::{
    psbt::{self, PartiallySignedTransaction},
    OutPoint, Script, Transaction, TxIn, TxOut, Txid, Witness,
};

use crate::AnalysisResult;
type Result<T> = std::result::Result<T, Error>;
type Psbt = PartiallySignedTransaction;

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
