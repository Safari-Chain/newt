use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
extern crate hex as hexfunc;

use bitcoin::blockdata::{opcodes, script};
use bitcoin::consensus::{encode};
use bitcoin::hashes::hex::{self, FromHex};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Message, Secp256k1, Signing, Verification};
use bitcoin::util::address::{self, WitnessVersion};
use bitcoin::util::amount::ParseAmountError;
use bitcoin::util::bip32::{
    self, ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey, Fingerprint,
    IntoDerivationPath,
};
use bitcoin::util::psbt::{
    self, serialize::Deserialize, Input, PartiallySignedTransaction, PsbtSighashType,
};
use bitcoin::util::sighash::SighashCache;
use bitcoin::{
    Address, Amount, EcdsaSig, EcdsaSighashType, Network, OutPoint, PrivateKey, PublicKey, Script,
    Sighash, Transaction, TxIn, TxOut, Txid, Witness, AddressType,
};

type Result<T> = std::result::Result<T, Error>;
type Psbt = PartiallySignedTransaction;

// Get this from the output of `bt dumpwallet <file>`.
const EXTENDED_MASTER_PRIVATE_KEY: &str = "tprv8ZgxMBicQKsPeSHZFZWT8zxie2dXWcwemnTkf4grVzMvP2UABUxqbPTCHzZ4ztwhBghpfFw27sJqEgW6y1ZTZcfvCUdtXE1L6qMF7TBdbqQ";

// Set these with valid data from output of step 5 above. Please note, input utxo must be a p2wpkh.
const INPUT_UTXO_TXID: &str = "295f06639cde6039bf0c3dbf4827f0e3f2b2c2b476408e2f9af731a8d7a9c7fb";
const INPUT_UTXO_VOUT: u32 = 0;
const INPUT_UTXO_SCRIPT_PUBKEY: &str = "00149891eeb8891b3e80a2a1ade180f143add23bf5de";
const INPUT_UTXO_VALUE: &str = "50 BTC";

// Get this from the desciptor,
// "wpkh([97f17dca/0'/0'/0']02749483607dafb30c66bd93ece4474be65745ce538c2d70e8e246f17e7a4e0c0c)#m9n56cx0".
const INPUT_UTXO_DERIVATION_PATH: &str = "m/0h/0h/0h";

// Grab an address to receive on: `bt generatenewaddress` (obviously contrived but works as an example).
const RECEIVE_ADDRESS: &str = "bcrt1qcmnpjjjw78yhyjrxtql6lk7pzpujs3h244p7ae"; // The address to receive the coins we send.

const OUTPUT_AMOUNT_BTC: &str = "1 BTC";
const CHANGE_AMOUNT_BTC: &str = "48.99999 BTC"; // 1000 sat transaction fee.

const NETWORK: Network = Network::Regtest;

fn main() -> Result<()> {
    let secp = Secp256k1::new();

    let (offline, fingerprint, account_0_xpub, input_xpub) =
        ColdStorage::new(&secp, EXTENDED_MASTER_PRIVATE_KEY)?;

    let online = WatchOnly::new(account_0_xpub, input_xpub, fingerprint);

    let created = online.create_psbt(&secp)?;
    let updated = online.update_psbt(created)?;

    let signed = offline.sign_psbt(&secp, updated)?;

    let finalized = online.finalize_psbt(signed)?;

    // You can use `bt sendrawtransaction` to broadcast the extracted transaction.
    let tx = finalized.extract_tx();
    tx.verify(|_| Some(previous_output()))
        .expect("failed to verify transaction");

    let hexstring = encode::serialize_hex(&tx);
    println!(
        "You should now be able to broadcast the following transaction: \n\n{}",
        hexstring
    );

    let tx = decode_txn(hexstring);
    let analysis_result = check_multi_script(tx);
    println!("Analysis result: {:?}", analysis_result);

    Ok(())
}

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
    let result = outputs.into_iter().all(|vout| {
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



// We cache the pubkeys for convenience because it requires a scep context to convert the private key.
/// An example of an offline signer i.e., a cold-storage device.
struct ColdStorage {
    /// The master extended private key.
    master_xpriv: ExtendedPrivKey,
    /// The master extended public key.
    master_xpub: ExtendedPubKey,
}

/// The data exported from an offline wallet to enable creation of a watch-only online wallet.
/// (wallet, fingerprint, account_0_xpub, input_utxo_xpub)
type ExportData = (ColdStorage, Fingerprint, ExtendedPubKey, ExtendedPubKey);

impl ColdStorage {
    /// Constructs a new `ColdStorage` signer.
    ///
    /// # Returns
    ///
    /// The newly created signer along with the data needed to configure a watch-only wallet.
    fn new<C: Signing>(secp: &Secp256k1<C>, xpriv: &str) -> Result<ExportData> {
        let master_xpriv = ExtendedPrivKey::from_str(xpriv)?;
        let master_xpub = ExtendedPubKey::from_priv(secp, &master_xpriv);

        // Hardened children require secret data to derive.

        let path = "m/84h/0h/0h".into_derivation_path()?;
        let account_0_xpriv = master_xpriv.derive_priv(secp, &path)?;
        let account_0_xpub = ExtendedPubKey::from_priv(secp, &account_0_xpriv);

        let path = INPUT_UTXO_DERIVATION_PATH.into_derivation_path()?;
        let input_xpriv = master_xpriv.derive_priv(secp, &path)?;
        let input_xpub = ExtendedPubKey::from_priv(secp, &input_xpriv);

        let wallet = ColdStorage {
            master_xpriv,
            master_xpub,
        };
        let fingerprint = wallet.master_fingerprint();

        Ok((wallet, fingerprint, account_0_xpub, input_xpub))
    }

    /// Returns the fingerprint for the master extended public key.
    fn master_fingerprint(&self) -> Fingerprint {
        self.master_xpub.fingerprint()
    }

    /// Signs `psbt` with this signer.
    fn sign_psbt<C: Signing>(&self, secp: &Secp256k1<C>, mut psbt: Psbt) -> Result<Psbt> {
        let sk = self.private_key_to_sign(secp, &psbt.inputs[0])?;
        sign_psbt(secp, &sk, &mut psbt, 0)?;

        Ok(psbt)
    }

    /// Returns the private key required to sign `input` if we have it.
    fn private_key_to_sign<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        input: &Input,
    ) -> Result<PrivateKey> {
        match input.bip32_derivation.iter().nth(0) {
            Some((pk, (fingerprint, path))) => {
                if *fingerprint != self.master_fingerprint() {
                    return Err(Error::WrongFingerprint);
                }

                let sk = self.master_xpriv.derive_priv(secp, &path)?.to_priv();
                if *pk != sk.public_key(secp).inner {
                    return Err(Error::WrongPubkey);
                }

                Ok(sk)
            }
            None => Err(Error::MissingBip32Derivation),
        }
    }
}

/// An example of an watch-only online wallet.
struct WatchOnly {
    /// The xpub for account 0 derived from derivation path "m/84h/0h/0h".
    account_0_xpub: ExtendedPubKey,
    /// The xpub derived from `INPUT_UTXO_DERIVATION_PATH`.
    input_xpub: ExtendedPubKey,
    /// The master extended pubkey fingerprint.
    master_fingerprint: Fingerprint,
}

impl WatchOnly {
    /// Constructs a new watch-only wallet.
    ///
    /// A watch-only wallet would typically be online and connected to the Bitcoin network. We
    /// 'import' into the wallet the `account_0_xpub` and `master_fingerprint`.
    ///
    /// The reason for importing the `input_xpub` is so one can use bitcoind to grab a valid input
    /// to verify the workflow presented in this file.
    fn new(
        account_0_xpub: ExtendedPubKey,
        input_xpub: ExtendedPubKey,
        master_fingerprint: Fingerprint,
    ) -> Self {
        WatchOnly {
            account_0_xpub,
            input_xpub,
            master_fingerprint,
        }
    }

    /// Creates the PSBT, in BIP174 parlance this is the 'Creater'.
    fn create_psbt<C: Verification>(&self, secp: &Secp256k1<C>) -> Result<Psbt> {
        let to_address = Address::from_str(RECEIVE_ADDRESS)?;
        let to_amount = Amount::from_str(OUTPUT_AMOUNT_BTC)?;

        let (_, change_address, _) = self.change_address(secp)?;
        let change_amount = Amount::from_str(CHANGE_AMOUNT_BTC)?;

        let tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_hex(INPUT_UTXO_TXID)?,
                    vout: INPUT_UTXO_VOUT,
                },
                script_sig: Script::new(),
                sequence: 0xFFFFFFFF, // Ignore nSequence.
                witness: Witness::default(),
            }],
            output: vec![
                TxOut {
                    value: to_amount.as_sat(),
                    script_pubkey: to_address.script_pubkey(),
                },
                TxOut {
                    value: change_amount.as_sat(),
                    script_pubkey: change_address.script_pubkey(),
                },
            ],
        };

        let psbt = Psbt::from_unsigned_tx(tx)?;

        Ok(psbt)
    }

    /// Updates the PSBT, in BIP174 parlance this is the 'Updater'.
    fn update_psbt(&self, mut psbt: Psbt) -> Result<Psbt> {
        let mut input = Input::default();

        input.witness_utxo = Some(previous_output());

        let pk = self.input_xpub.to_pub();
        let wpkh = pk.wpubkey_hash().expect("a compressed pubkey");

        let redeem_script = Script::new_v0_p2wpkh(&wpkh);
        input.redeem_script = Some(redeem_script);

        let fingerprint = self.master_fingerprint;
        let path = input_derivation_path()?;
        let mut map = BTreeMap::new();
        map.insert(pk.inner, (fingerprint, path));
        input.bip32_derivation = map;

        let ty = PsbtSighashType::from_str("SIGHASH_ALL").map_err(|_| Error::SighashTypeParse)?;
        input.sighash_type = Some(ty);

        psbt.inputs = vec![input];

        Ok(psbt)
    }

    /// Returns data for the first change address (standard BIP84 derivation path
    /// "m/84h/0h/0h/1/0"). A real wallet would have access to the chain so could determine if an
    /// address has been used or not. We ignore this detail and just re-use the first change address
    /// without loss of generality.
    fn change_address<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
    ) -> Result<(PublicKey, Address, DerivationPath)> {
        let path = vec![
            ChildNumber::from_normal_idx(1)?,
            ChildNumber::from_normal_idx(0)?,
        ];
        let derived = self.account_0_xpub.derive_pub(secp, &path)?;

        let pk = derived.to_pub();
        let addr = Address::p2wpkh(&pk, NETWORK)?;
        let path = path.into_derivation_path()?;

        Ok((pk, addr, path))
    }

    /// Finalizes the PSBT, in BIP174 parlance this is the 'Finalizer'.
    fn finalize_psbt(&self, mut psbt: Psbt) -> Result<Psbt> {
        use bitcoin::util::psbt::serialize::Serialize;

        if psbt.inputs.is_empty() {
            return Err(Error::InputsEmpty);
        }

        // TODO: Remove this explicit scope once we bump MSRV. The Rust 1.29 borrow checker is not
        // sophisticated enough to handle the immutable and mutable borrow of psbt.inputs[0].
        let script_witness = {
            let sigs: Vec<_> = psbt.inputs[0].partial_sigs.values().collect();
            let mut script_witness: Witness = Witness::new();

            script_witness.push(&sigs[0].serialize());
            script_witness.push(self.input_xpub.to_pub().serialize());

            script_witness
        };
        psbt.inputs[0].final_script_witness = Some(script_witness);

        // Clear all the data fields as per the spec.
        psbt.inputs[0].partial_sigs = BTreeMap::new();
        psbt.inputs[0].sighash_type = None;
        psbt.inputs[0].redeem_script = None;
        psbt.inputs[0].witness_script = None;
        psbt.inputs[0].bip32_derivation = BTreeMap::new();

        Ok(psbt)
    }
}

fn input_derivation_path() -> Result<DerivationPath> {
    let path = INPUT_UTXO_DERIVATION_PATH.into_derivation_path()?;
    Ok(path)
}

fn previous_output() -> TxOut {
    let script_pubkey = Script::from_hex(INPUT_UTXO_SCRIPT_PUBKEY)
        .expect("failed to parse input utxo scriptPubkey");
    let amount = Amount::from_str(INPUT_UTXO_VALUE).expect("failed to parse input utxo value");

    TxOut {
        value: amount.as_sat(),
        script_pubkey,
    }
}

/// Signs `psbt` input at `input_index` using `sk`.
fn sign_psbt<C: Signing>(
    secp: &Secp256k1<C>,
    sk: &PrivateKey,
    psbt: &mut Psbt,
    input_index: usize,
) -> std::result::Result<(), SignError> {
    if input_index >= psbt.inputs.len() || input_index >= psbt.unsigned_tx.input.len() {
        return Err(SignError::InputIndexOutOfRange);
    }

    if psbt.inputs[input_index].final_script_sig.is_some()
        || psbt.inputs[input_index].final_script_witness.is_some()
    {
        return Ok(());
    }

    let pubkey = sk.public_key(secp);
    if psbt.inputs[input_index].partial_sigs.contains_key(&pubkey) {
        return Ok(());
    }

    let (hash, sighash_type) = match psbt.inputs[input_index].witness_utxo {
        Some(_) => segwit_v0_sighash(psbt, input_index)?,
        None => legacy_sighash(psbt, input_index)?,
    };

    // From BIP: Before signing a non-witness input, the Signer must verify that the TXID of the
    // non-witness UTXO matches the TXID specified in the unsigned transaction.
    if let Some(tx) = &psbt.inputs[input_index].non_witness_utxo {
        if tx.txid() != psbt.unsigned_tx.input[input_index].previous_output.txid {
            return Err(SignError::InvalidTxid);
        }
    }

    // From BIP: Before signing a witness input, the Signer must verify that the witnessScript (if
    // provided) matches the hash specified in the UTXO or the redeemScript, and the redeemScript
    // (if provided) matches the hash in the UTXO.
    if let Some(tx) = &psbt.inputs[input_index].witness_utxo {
        if let Some(witness_script) = &psbt.inputs[input_index].witness_script {
            let script_pubkey =
                Script::new_witness_program(WitnessVersion::V0, &witness_script.wscript_hash());
            if script_pubkey != tx.script_pubkey {
                match &psbt.inputs[input_index].redeem_script {
                    Some(redeem_script) => {
                        if witness_script != redeem_script {
                            return Err(SignError::WitnessScriptMismatch);
                        }
                    }
                    None => return Err(SignError::WitnessScriptMismatch),
                }
            }
        }

        if let Some(redeem_script) = &psbt.inputs[input_index].redeem_script {
            if *redeem_script != tx.script_pubkey {
                return Err(SignError::RedeemScriptMismatch);
            }
        }
    }

    let signature = secp.sign_ecdsa(
        &Message::from_slice(&hash.into_inner()[..]).unwrap(),
        &sk.inner,
    );

    let mut final_signature = Vec::with_capacity(75);
    final_signature.extend_from_slice(&signature.serialize_der());
    final_signature.push(sighash_type.to_u32() as u8);

    let mut map = BTreeMap::new();
    map.insert(
        pubkey,
        EcdsaSig::from_slice(&final_signature).map_err(|_| SignError::Ecdsa)?,
    );
    psbt.inputs[input_index].partial_sigs = map;

    Ok(())
}

// Copied directly from `impl ComputeSighash for Legacy` in `bdk`.
fn legacy_sighash(
    psbt: &Psbt,
    input_index: usize,
) -> std::result::Result<(Sighash, EcdsaSighashType), SignError> {
    if input_index >= psbt.inputs.len() || input_index >= psbt.unsigned_tx.input.len() {
        return Err(SignError::InputIndexOutOfRange);
    }

    let psbt_input = &psbt.inputs[input_index];
    let tx_input = &psbt.unsigned_tx.input[input_index];

    let sighash = psbt_input
        .sighash_type
        .unwrap_or(PsbtSighashType::from(EcdsaSighashType::All));
    let script = match psbt_input.redeem_script {
        Some(ref redeem_script) => redeem_script.clone(),
        None => {
            let non_witness_utxo = psbt_input
                .non_witness_utxo
                .as_ref()
                .ok_or(SignError::MissingNonWitnessUtxo)?;
            let prev_out = non_witness_utxo
                .output
                .get(tx_input.previous_output.vout as usize)
                .ok_or(SignError::InvalidNonWitnessUtxo)?;

            prev_out.script_pubkey.clone()
        }
    };

    Ok((
        psbt.unsigned_tx
            .signature_hash(input_index, &script, sighash.to_u32()),
        sighash.ecdsa_hash_ty().map_err(|_| SignError::Ecdsa)?,
    ))
}

// Copied directly from `impl ComputeSighash for Segwitv0` in `bdk`.
fn segwit_v0_sighash(
    psbt: &Psbt,
    input_index: usize,
) -> std::result::Result<(Sighash, EcdsaSighashType), SignError> {
    if input_index >= psbt.inputs.len() || input_index >= psbt.unsigned_tx.input.len() {
        return Err(SignError::InputIndexOutOfRange);
    }

    let psbt_input = &psbt.inputs[input_index];
    let tx_input = &psbt.unsigned_tx.input[input_index];

    let sighash = psbt_input
        .sighash_type
        .unwrap_or(PsbtSighashType::from(EcdsaSighashType::All));

    // Always try first with the non-witness utxo.
    let utxo = if let Some(prev_tx) = &psbt_input.non_witness_utxo {
        // Check the provided prev-tx
        if prev_tx.txid() != tx_input.previous_output.txid {
            return Err(SignError::InvalidNonWitnessUtxo);
        }

        // The output should be present, if it's missing the `non_witness_utxo` is invalid.
        prev_tx
            .output
            .get(tx_input.previous_output.vout as usize)
            .ok_or(SignError::InvalidNonWitnessUtxo)?
    } else if let Some(witness_utxo) = &psbt_input.witness_utxo {
        // Fallback to the witness_utxo. If we aren't allowed to use it, signing should fail
        // before we get to this point.
        witness_utxo
    } else {
        // Nothing has been provided.
        return Err(SignError::MissingNonWitnessUtxo);
    };
    let value = utxo.value;

    let script = match psbt_input.witness_script {
        Some(ref witness_script) => witness_script.clone(),
        None => {
            if utxo.script_pubkey.is_v0_p2wpkh() {
                p2wpkh_script_code(&utxo.script_pubkey)
            } else if psbt_input
                .redeem_script
                .as_ref()
                .map(Script::is_v0_p2wpkh)
                .unwrap_or(false)
            {
                p2wpkh_script_code(psbt_input.redeem_script.as_ref().unwrap())
            } else {
                return Err(SignError::MissingWitnessScript);
            }
        }
    };

    Ok((
        SighashCache::new(&psbt.unsigned_tx)
            .segwit_signature_hash(
                input_index,
                &script,
                value,
                sighash.ecdsa_hash_ty().map_err(|_| SignError::Ecdsa)?,
            )
            .map_err(|_| SignError::Sighash)?,
        sighash.ecdsa_hash_ty().map_err(|_| SignError::Ecdsa)?,
    ))
}

fn p2wpkh_script_code(script: &Script) -> Script {
    script::Builder::new()
        .push_opcode(opcodes::all::OP_DUP)
        .push_opcode(opcodes::all::OP_HASH160)
        .push_slice(&script[2..])
        .push_opcode(opcodes::all::OP_EQUALVERIFY)
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script()
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Error {
    /// Bip32 error.
    Bip32(bip32::Error),
    /// PSBT error.
    Psbt(psbt::Error),
    /// Bitcoin_hashes hex error.
    Hex(hex::Error),
    /// Address error.
    Address(address::Error),
    /// Parse amount error.
    ParseAmount(ParseAmountError),
    /// Signing error.
    Sign(SignError),
    /// Parsing sighash type string failed.
    SighashTypeParse,
    /// PSBT inputs field is empty.
    InputsEmpty,
    /// BIP32 data missing.
    MissingBip32Derivation,
    /// Fingerprint does not match that in input.
    WrongFingerprint,
    /// Pubkey for derivation path does not match that in input.
    WrongPubkey,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {}

impl From<bip32::Error> for Error {
    fn from(e: bip32::Error) -> Error {
        Error::Bip32(e)
    }
}

impl From<psbt::Error> for Error {
    fn from(e: psbt::Error) -> Error {
        Error::Psbt(e)
    }
}

impl From<hex::Error> for Error {
    fn from(e: hex::Error) -> Error {
        Error::Hex(e)
    }
}

impl From<address::Error> for Error {
    fn from(e: address::Error) -> Error {
        Error::Address(e)
    }
}

impl From<ParseAmountError> for Error {
    fn from(e: ParseAmountError) -> Error {
        Error::ParseAmount(e)
    }
}

impl From<SignError> for Error {
    fn from(e: SignError) -> Error {
        Error::Sign(e)
    }
}

/// Signing error.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SignError {
    /// Input index is out of range
    InputIndexOutOfRange,
    /// The `non_witness_utxo` field of the transaction is required to sign this input
    MissingNonWitnessUtxo,
    /// The `non_witness_utxo` specified is invalid
    InvalidNonWitnessUtxo,
    /// The `witness_script` field of the transaction is required to sign this input
    MissingWitnessScript,
    /// bitcoin::ecdsa error.
    Ecdsa,
    /// Sighash encoding error.
    Sighash,
    /// BIP174: non-witness input txid must match txid of unsigned transaction.
    InvalidTxid,
    /// BIP174: witness script must match the hash in the scriptPubkey.
    WitnessScriptMismatch,
    /// BIP174: redeem script must match the scriptPubkey.
    RedeemScriptMismatch,
    /// BIP174: redeem script must match the hash in the UTXO.
    ScritpPubkeyMismatch,
}
