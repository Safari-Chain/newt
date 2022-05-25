use bitcoin::{Script, Network, AddressType, TxOut};
use bitcoin::{Transaction, hashes::hex::FromHex};
use bitcoin::consensus::deserialize;
use bitcoin::util::address::{self};

const NETWORK: Network = Network::Bitcoin;

pub fn decode_txn(hex_str: String) -> Transaction {
    let tx_bytes = Vec::from_hex(&hex_str).unwrap();
    let tx = deserialize(&tx_bytes).unwrap();
    return tx;
}

pub fn script_to_addr(script: Script) -> address::Address {
    let addr = address::Address::from_script(&script, NETWORK).unwrap();
    addr
}

pub fn get_address_type(vouts: Vec<TxOut>) -> Vec<AddressType> {
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

pub fn parse_input_tx(txn_in: String, vout_index: usize) -> AddressType {
    let tx = decode_txn(txn_in);
    let outputs = tx.output;
    let addr_type = *get_address_type(outputs.clone()).get(vout_index).unwrap();
    return addr_type;
}