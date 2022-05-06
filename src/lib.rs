extern crate hex as hexfunc;


use bitcoin::util::address;
use bitcoin::util::psbt::{ serialize::Deserialize };
use bitcoin::{ Network, Script, Transaction, TxOut, AddressType };

const NETWORK: Network = Network::Regtest;

#[derive(Debug)]
struct AnalysisResult {
    heuristic: String,
    result: bool,
    scripts: Vec<String>,
    details: String,
}

/// Multi-script heuristic
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
    let address_type = vouts.into_iter().map(|vout| {
        let addr = script_to_addr(vout.script_pubkey.clone());
        let addr_type = address::Address::address_type(&addr).unwrap();
        return addr_type;
    }).collect();
    return address_type;
}

// 3. check for multi-script types using addresses
fn check_multi_script(txn: Transaction) -> AnalysisResult {
    let outputs = txn.output;
    let addr_types = get_address_type(outputs.clone()).clone();
    let first_addr_type = addr_types.get(0).unwrap();
    let result = !outputs.into_iter().all(|vout| {
        let addr = script_to_addr(vout.script_pubkey.clone());
        let addr_type = address::Address::address_type(&addr).unwrap();
        return addr_type == first_addr_type.clone();
    });

   let script_types: Vec<String> = addr_types.into_iter().map(|addr| addr.to_string()).collect();
   let details = if result { "Multi-script" } else { "Single-script" };
    return AnalysisResult {
        heuristic: String::from("Mixed script heuristics!"),
        result,
        scripts: script_types,
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
            heuristic: String::from("Mixed script heuristics!"),
            result: false,
            scripts: vec![String::from("p2wpkh")],
            details: String::from("Single-script"),
        };
        
        let tx = decode_txn(tx_hex_str);
        let analysis_result = check_multi_script(tx);

        assert_eq!(expected_result.heuristic, analysis_result.heuristic);
        assert_eq!(expected_result.result, analysis_result.result);
        assert_eq!(expected_result.scripts, analysis_result.scripts);
        assert_eq!(expected_result.details, analysis_result.details);
    }
}
