use bitcoin::util::address::{self, Address};
use clap::Parser;
use newt::{
    break_address_reuse_template, break_multiscript_template, break_unnecessary_input_template,
    check_address_reuse, check_common_input_ownership, check_equaloutput_coinjoin,
    check_multi_script, check_round_number, check_unnecessary_input, decode_txn,
    transaction_analysis,
};
use std::collections::HashMap;
use std::str::FromStr;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// arguement for multiscript
    #[clap(long)]
    multiscript: Option<String>,

    #[clap(long)]
    addressreuse: Option<String>,

    #[clap(long)]
    roundnumber: Option<String>,

    #[clap(long)]
    coinjoin: Option<String>,

    #[clap(long)]
    unnecessaryinputs: Option<String>,

    #[clap(long)]
    commonownership: Option<String>,

    #[clap(long)]
    analysis: Option<String>,

    #[clap(long)]
    break_address_reuse: Option<String>,

    #[clap(long)]
    break_multiscript: Option<String>,

    #[clap(long)]
    break_unnecessary_input: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    if let Some(tx_hex) = cli.multiscript.as_deref() {
        let tx = decode_txn(tx_hex.to_owned());
        let prev_tx_hex = String::from("01000000000101cb1c255d626dfbaea3557588725c779ebac6469e2c86a1d8647e6768751920100100000000ffffffff0259581000000000001600144c4afd82a9872b87836f0a4ee60250a0b857d0eaeb81020000000000160014ed7118d50af8e7e1f388d94972c23d5bb471c265024730440220199e11cffdc827ca91852416aa3263bdfadd95cd76c400f81e236a5cabcce18502202a4fe3cb84fe318d0c886e488d0b5ff099c6adfaa4bfce53a8d94bdb759dc1330121026c5f4446e09a7069f1b2bc35baf6a0ad9d7ed257fce5eac027a1c8466023fd5800000000");
        let analysis_result = check_multi_script(&tx, prev_tx_hex);
        println!("{:#?}", analysis_result);
    }

    if let Some(tx_hex) = cli.addressreuse.as_deref() {
        let mut prev_txns = HashMap::new();
        prev_txns.insert(String::from("1c3ea699a24a17dd99533837e5a9cde84e0517033cf1deba18e9baca53c305d2"), String::from("010000000195d76b18853ab39712192be5f90bf350302eafa0c51067ca59af7bcb183b4025090000006b483045022100ef3c03a1e200a51da0df7117f0a7bcdef3c72b6c269be5123b404e5999b3a00002205e64a0392bd4dc2c7bc32f4a7978ddfbb440e0d9e504a71404fd8e05f88e3db001210256ba3dec93e8fda4485a8dea428d94aa968b509ec4ac430bf0de5f9027f988c8ffffffff0a09f006000000000017a91415adeb31f7415cbabafd07af8d90875d350655bc87989b58000000000017a914f384976b6e07df4c9bd7a212995ac4509e6c7d4787bc9b0c00000000001976a9149fdd37db4058fce4eeff3fca4bc5551590c9187d88ac5e163500000000001976a914bd28982b11113bfa720c3ff34ac9d09f8c6fb40f88ac806f4a0c000000001976a914e16873335e04467e02d8eb143f1302c685b8f31f88ac88e55a000000000017a9149907fae571a857e66ff83c4d70fa82e1286b06be876c796202000000001976a914981476e141da8d847b814b832e6402cd7338c6d188ac5896ec01000000001976a914c288197330741bc85587f4f00ee48c66e3be319488ac7f8446060000000017a9145d76ef27663a41a4a054d00886367e4a56e24e06874ffe9cc3000000001976a914e5fc50dec180de9a3c1c8f0309506321ae88def988ac00000000"));
        let curr_tx = decode_txn(tx_hex.to_owned());
        let analysis_result = check_address_reuse(&curr_tx, &prev_txns);
        println!("{:#?}", analysis_result);
    }

    if let Some(tx_hex) = cli.roundnumber.as_deref() {
        let tx = decode_txn(tx_hex.to_owned());
        let analysis_result = check_round_number(&tx);
        println!("{:#?}", analysis_result);
    }

    if let Some(tx_hex) = cli.coinjoin.as_deref() {
        let tx = decode_txn(tx_hex.to_owned());
        let analysis_result = check_equaloutput_coinjoin(&tx);
        println!("{:#?}", analysis_result);
    }

    if let Some(tx_hex) = cli.unnecessaryinputs.as_deref() {
        let mut prev_txns = HashMap::new();
        prev_txns.insert(String::from("1c3ea699a24a17dd99533837e5a9cde84e0517033cf1deba18e9baca53c305d2"), String::from("010000000195d76b18853ab39712192be5f90bf350302eafa0c51067ca59af7bcb183b4025090000006b483045022100ef3c03a1e200a51da0df7117f0a7bcdef3c72b6c269be5123b404e5999b3a00002205e64a0392bd4dc2c7bc32f4a7978ddfbb440e0d9e504a71404fd8e05f88e3db001210256ba3dec93e8fda4485a8dea428d94aa968b509ec4ac430bf0de5f9027f988c8ffffffff0a09f006000000000017a91415adeb31f7415cbabafd07af8d90875d350655bc87989b58000000000017a914f384976b6e07df4c9bd7a212995ac4509e6c7d4787bc9b0c00000000001976a9149fdd37db4058fce4eeff3fca4bc5551590c9187d88ac5e163500000000001976a914bd28982b11113bfa720c3ff34ac9d09f8c6fb40f88ac806f4a0c000000001976a914e16873335e04467e02d8eb143f1302c685b8f31f88ac88e55a000000000017a9149907fae571a857e66ff83c4d70fa82e1286b06be876c796202000000001976a914981476e141da8d847b814b832e6402cd7338c6d188ac5896ec01000000001976a914c288197330741bc85587f4f00ee48c66e3be319488ac7f8446060000000017a9145d76ef27663a41a4a054d00886367e4a56e24e06874ffe9cc3000000001976a914e5fc50dec180de9a3c1c8f0309506321ae88def988ac00000000"));
        let curr_tx = decode_txn(tx_hex.to_owned());
        let analysis_result = check_unnecessary_input(&curr_tx, &prev_txns);
        println!("{:#?}", analysis_result);
    }

    if let Some(tx_hex) = cli.commonownership.as_deref() {
        let mut prev_txns = HashMap::new();
        prev_txns.insert(String::from("0ab7cb30a4ffd5185a38e6e0eddf62a48ffd437f417fd38bc26c3b22a8bdecf1"), String::from("01000000000105431e152d6bbb8999195dded08eaa2ffc2ca0deef50826348b023a88f4a3db1480300000000ffffffffe23fe51cf5acff1f97a2bfbb927edfeb23b09d8c171f84922048d7cfc8534e910200000000ffffffff44fee26fc02dc0de5feb7f3c8b0d9f5f394635476dffdeb8eb2f2f08f33e30a30400000000ffffffff982d8ab9d9ac013b48a0de70998c5a7d3408ff22511f114acd84687bb0adf9a31600000000ffffffff38c096e1cf2a811d2648403e4a56ad25ce1080ab84a0acd9664d0b862b3461d08c00000000ffffffff0540420f00000000001600140da6910d6b26915be0805efabf3d50d8358e282340420f00000000001600140ebbbc724902c4ff5479c900c5b13db4b7cc11bf40420f000000000016001420e96bcc789179721fbbb319300b4ecd2941fbca40420f00000000001600143ba605de380d5a4fb5ce5fbf287c87be380d864440420f0000000000160014a998e07e4c768916fb80a1c50e124653b1ccbf4a02483045022100b63f9d50edef3f70eb06a60d4a3b22d28399595f5a6bd0c74d3b7b106f942fd802206cf3db9654c5fe1b8b93de2daddab712510667e258fee71303bfb80d872441440121035ad05ccb684a855fe181a0675650297ab79e7e7171cc03b92fabf7b8d4b3959402483045022100833b18451e722f6d0e53d05699945a6db095fa92f60300a0bfb5cb85cd9a2a3402207dbb0e13fafe7c056e23e811ae79d55e2fcae851ec576bb06277ff92d22c71c0012103f4b03d582cd5699248a80af269fcc645ecc26becc761842230cac3d8413c51720247304402204324ef1521394e17c42eb4959c758d77e8336156de7ae321fb56a54c8ee57f4a02205c37b555f38e9b0d7cff9198165710fd2d59d0fe4520890e5342ea59a79acf56012102e4c8ca32d3e6f4abfe004f658a67f9f300b9c2d116e1fa291247e548d0bc4fca024730440220268432a70b8606852a9eec07b8fb2e0740b2d2d844eae80716ccfdbcda7e5dcf022043f073329f2ac9a96c39d122e183d4b04893389f5dfb702b026008ae4c4e780a012102f8b45b34ba6d73dce62d415e13e61afa34253d3d921097b1542935e8a7bc6fe302473044022033deefc1f7b56c41c62ce27f76a6032de917559c0d5889520d548adbbaa40ed3022007bf86f5d2701fcce5ba26097dd8cdf6c49f2b80e09233047ec6afa7e163eccd01210363cbd09fadc91fae0c0a9fad9d18ceb1c7413dcb70969fe34f04f929a1f645ff00000000"));
        prev_txns.insert(String::from("6db2860f73d16a4e54a4fd2e387e0eb10eb830a6209dc1ee1ca2e52679737b0c"), String::from("0100000000010192b209f003d203f9e72756963b95b762b4cfb788d99fbde6b1501bb56fbcfd9e0000000000ffffffff090000000000000000426a4057de40bbc4e3661114c519797a86b605c961f0cec568fa7597f1641c7723bdf72522df8a645abb001d24d6b979478ca39816243bb9fb8e3cb79d6a715dbb176050c300000000000016001478fca19ac504d63def5e15fdfa1b00c06b3186e25530030000000000160014ccd968ddb97952054cb0b0104d13e628f7358d9557490f000000000016001409adf657d5afe006f1697ef94a126746657ab9c057490f00000000001600143def4094b95655be042bae91c7057dd3267d62bd57490f00000000001600145c5a8407eb9994bffce72ec8b5fc2db1a877337c57490f00000000001600149025bd5e7ff9065440dd657f697d365e7b4bb4ca57490f00000000001600149bc0f8169f359f8d44dc554c48fa07623f38351e57490f0000000000160014bdf1c85ad9148974b91188653e087e73f2d5ef4602473044022070ac382afc2bd5dfe636dbe2d047725978bd2d2fc37677acb26b750ededcaed80220228ec67071d293f9046aae41a0890d027dcf5ce0727c1a8f2a1d40b027183a7d012102e0ba24e121fb45163cc570eb1e2ff648e6accceb1de92c8826b22ffe0979dce200000000"));
        prev_txns.insert(String::from("76ede963b0d732823e24798fd8944c4d0dcfb09b1a7c3da206c32f0ad8af9a67"), String::from("010000000001031081d69b995f1f97bacdf50ed2b4c6ba4afce36273c4ba53814fe0c3a2921407340000006a473044022000cf525ba34c3cc5df7259bde4aba148e64259f49fbd2d73268e6ca0087eee9c02204f39cc780a3f520d5a1ce2dc58551af2b63a980d3fd4c5e86d185670e200952e012102c1eb8406911d5d72e5f234ae0725144f21398b3c9f9956fc72f1ca45b209151afffffffff7833b6d036c05c8a666391d493c4817d0b3e910074d42e0ea3cce618e706f410000000000ffffffff245d59e95e77114c237259e85a187ebae062bab36970b856f7b32df6784c51430100000000ffffffff110000000000000000426a4030b086f664c1467e9dba4573ddffd3309486dc3ac6f3d6a81135f3930cd4ff641897c32d06bdd10d7048c41b2343002af2a9c024d7b3b327a534cb8f5ee603f450c30000000000001600145286b9c60138b902727ff20ccf6548c11568f0fbb190050000000000160014753cfea5cc01d9579d73c100558837466d246b8228480f000000000016001423a652f02eb7af96d54fca33170e675cd1ab28df28480f000000000016001423bec0fb6bfb41aa8452e0ec12122cc1de293c4628480f000000000016001424eebb26fd4cb1775b8b7295f838740f4b207eda28480f000000000016001429a8d862a8f4170864d5de9f0e156f35442dc0dc28480f00000000001600143695d8823eb5f9ac8cb00dd59f4db7d286455f7928480f000000000016001459478018a428a6104d23578c5261dd160cb07b1d28480f000000000016001460137dfcad3cc2fdf5ffd90309dab2fde5349f2528480f0000000000160014663c3207bbf527e7dc1dd8d0053917dbf3bc65e228480f00000000001600146e8eff9c029006d26f1378e1855681d1b0b44f0e28480f000000000016001472540586c8a5f25869705b384b0ed85f9108094528480f000000000016001483e4d6828b634f694cfc49e3ed1c694f7781f37628480f0000000000160014a3be255bbbb996f582f136621d093bb290651c3928480f0000000000160014c3b0b0ec229082d1e549e6b44bf52fc5c783b42e28480f0000000000160014e48c746dcf75801c4cb32df41f1189aff60621f30002483045022100b9589ca25bad58f017661ebdd7bf53039b5b97bfa2fcf561ff1cf9f2bbbb44c202205e45772b268a33dcafec5d1d13c683a7b61f5b1aa54c2e8f6943bb620e5e476401210240daa3096f01381ce2804bc87cdd61f274ad9f16d6d49aa495dedd574c24b181024730440220101c2605be3d60a39682e16e50b10aabec39391a5f192af9dbcb1842a04f2ce902200ab7e9427b4d1839ee44f713d511ba8c47eb57a5ed6b99275004baf682539fc50121024e2252d10a0ada99b6c49c39735e0b8760c62e55b2a843a934813cfde97af64700000000"));
        prev_txns.insert(String::from("7bafc86ae92cdd3a2ae9600d11dbcb41e66d8f2bca3231843e53a9808da60fe3"), String::from("01000000000105a63ab0aa7b35a4100a70a4bd055a7f22f09e2208d4fbcbe2d7ea4135009357180400000000ffffffffa773ce7f00e9ccfb6cf7c0c2f8af5f57a2078e4ebbdd057634121e400fab5c250400000000ffffffff022a63a18a20b6df21da4dcab91c721eaf7bd7ce3b863acf8041c351f99476a50000000000ffffffff00bbeceb2ad18849f7f81f44a4e681e03091198d672a9d667cddbcd3fbbc73b00200000000ffffffffefec194c1cf5ee4d4405851a963710887da504463c04b1fd5b6d4257d7294bb70600000000ffffffff0540420f00000000001600142335a77e481b083ee6dc96c7b3a66df842bff08b40420f00000000001600145ff469b1b935f1b6770f4da64499942027216f0340420f00000000001600147496b5b19011ec9a184072fbd925b91a203dcbea40420f0000000000160014ab07696bf78c46f5364ea2b10cd19b6da7ef346e40420f0000000000160014bd0c488616a1ef28c76fda0aa8a9f100f3a9eca702473044022024d8641eca58c60016b610ca6beb6f4402abe33a8b8db944e18a523c2b0ff57f0220022da6730262c380d7441ea8585098dba76efbdcbee2b1fcf5b8d06139bf995e0121025f10beb134d2d6ea2b7d73bc739f3e71adef202ef2cb8218771712819bc2c7f20247304402203d3641686a30da1dab7d1b92cba7d2e6d2956a7a1062c312a73c490f7c1b4cf302207919eba6af8731b941e5a4bee459f487f8d493a6899e8ac6c54ff9d34b438bab012103341da0d8542dbc8e1de9b5dbf7dbd052790c891c339a790a2cae3d3b92a1e3ec02483045022100d254738816ff902db174fbf3338ad998cac0793ee5be031e123dd5f0c635f08c02206def61dec9d95ea390bd16c9e7049ff74d05d8cbab6634877f54a12594aa014d01210368dea4147ca31431a4c68a85661f4f08c222cb4b7d65c57c694476efbbadbbe802483045022100d5349c628e5228560167d588e4865a1080a978d495f038e7b00ec8e5a5a5dc6a02201cac2ef74dbccf51efb9bab9321ea07e9b222876f084c711d2ddb8f6df303ec701210226c076ffbecc196412c018b4ba6941f1b92da0a10d5e8841059f94f98819b4480247304402206317bd0bc8bcf6f741f6e8dc46e3ac3228d86d4a741a825f5a5fd7c0b412e71702203acb635484ed6c4deafb13a57a8e4efa1e9bd50dac5ce2e2d7c8152a683c2afc012103607be345b9e8bb3a6d94ad12bfac23af849e123184fc970afbda77cb32ee17bc00000000"));
        prev_txns.insert(String::from("87095303bc59292ddf60a2904303697e83b96131b94f399857d24de081da66ae"), String::from("010000000001019a84949654b7b83c75675ac3bd026380fbaf9d90391057f53b3043b6a10a635d0000000000ffffffff040000000000000000426a409f51dfdf7584cb3971cd17406537ea739a9a1ba4f57e5600f4e447210b5a6362eb6582204a61650ebe1fa83168d5dbc4720d4bc615bc3719b993f125e3df4ad0d535000000000000160014ac930a7c44a628cf909273b0d401a6bc61294eaf50c3000000000000160014240272cad422987ece94e5d3e7946a50be4f06101a680f00000000001600147b6b4d27cbb1f328b2d2393dd78fb3c1a97e85f7024730440220484180d13b6237a9b5313cb6f0f317953870926692eb5c18215dd71a67e24d0f02206d2807b48d8680705a56637dd5a653ed0170dcb6088fa4b5bab18eac7be1815701210376fbcd19eb2ccca98e781453c6c15651cb8f293c21de1b8dfdf68a0531990ee100000000"));
        let curr_tx = decode_txn(tx_hex.to_owned());
        let analysis_result = check_common_input_ownership(&curr_tx, &prev_txns);
        println!("{:#?}", analysis_result);
    }

    if let Some(tx_hex) = cli.analysis.as_deref() {
        let mut prev_txns = HashMap::new();
        prev_txns.insert(String::from("1c3ea699a24a17dd99533837e5a9cde84e0517033cf1deba18e9baca53c305d2"), String::from("010000000195d76b18853ab39712192be5f90bf350302eafa0c51067ca59af7bcb183b4025090000006b483045022100ef3c03a1e200a51da0df7117f0a7bcdef3c72b6c269be5123b404e5999b3a00002205e64a0392bd4dc2c7bc32f4a7978ddfbb440e0d9e504a71404fd8e05f88e3db001210256ba3dec93e8fda4485a8dea428d94aa968b509ec4ac430bf0de5f9027f988c8ffffffff0a09f006000000000017a91415adeb31f7415cbabafd07af8d90875d350655bc87989b58000000000017a914f384976b6e07df4c9bd7a212995ac4509e6c7d4787bc9b0c00000000001976a9149fdd37db4058fce4eeff3fca4bc5551590c9187d88ac5e163500000000001976a914bd28982b11113bfa720c3ff34ac9d09f8c6fb40f88ac806f4a0c000000001976a914e16873335e04467e02d8eb143f1302c685b8f31f88ac88e55a000000000017a9149907fae571a857e66ff83c4d70fa82e1286b06be876c796202000000001976a914981476e141da8d847b814b832e6402cd7338c6d188ac5896ec01000000001976a914c288197330741bc85587f4f00ee48c66e3be319488ac7f8446060000000017a9145d76ef27663a41a4a054d00886367e4a56e24e06874ffe9cc3000000001976a914e5fc50dec180de9a3c1c8f0309506321ae88def988ac00000000"));

        let analysis_result_list = transaction_analysis(tx_hex.to_owned(), false, prev_txns);

        println!("{:#?}", analysis_result_list);
    }

    if let Some(tx_hex) = cli.break_address_reuse.as_deref() {
        let curr_tx_hex = tx_hex.to_owned();
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

        println!("{:#?}", psbt_tx);
    }

    if let Some(tx_hex) = cli.break_multiscript.as_deref() {
        let change_addr = Address::from_str("bc1q8jnnr6d8wvtzymrngrzhu3p5hrff2cx9a6fshj").unwrap();

        let mut tx = decode_txn(tx_hex.to_owned());
        let psbt = break_multiscript_template(&mut tx, Some(change_addr)).unwrap();

        println!("{:#?}", psbt);
    }

    /*if let Some(tx_hex) = cli.break_unnecessary_input.as_deref() {
        let tx = decode_txn(tx_hex.to_owned());
        let mut prev_txns = HashMap::new();
        prev_txns.insert(String::from("44141d713c616a49b48f6289d0a94c04498ce84db6106aa81078840a221d0bf5"), String::from("020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff050295000101ffffffff0200f2052a010000001600147a690d45185ebe54967f0735c48c48e86835932a0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000"));
        prev_txns.insert(String::from("b9865cb28d3e17ae4779f6be743a0cd5943240077f8084404ca82c39b5b24bd1"), String::from("020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff050288000101ffffffff0200f2052a010000001600147a690d45185ebe54967f0735c48c48e86835932a0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000"));
        prev_txns.insert(String::from("e20a44743301a90d009aa8a6dd32f95b39bf8cfe4d05ecc957657777e022bb79"), String::from("020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff05029c000101ffffffff0200f90295000000001600147a690d45185ebe54967f0735c48c48e86835932a0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000"));
        

        let mut tx = decode_txn(tx_hex.to_owned());
        let psbt = break_unnecessary_input_template(utxo, &mut tx).unwrap();

        println!("{:#?}", psbt);
    }*/
}

/*
accept comands from the user in the terminal
print the result to the console
commands to accept include:
1. command for each heuristic e.g. cargo run --multiscript
(a) multiscript
    cargo run --multiscript transaction-hex
(b) address-reuse
    cargo run --addressreuse transaction-hex
(c) round-number
    cargo run --roundnumber transaction-hex
(d) equal-output coinjoin
    cargo run --coinjoin transaction-hex
(e) unnecessary inputs
    cargo run --unnecessaryinputs transaction-hex
(f) common input ownership
    cargo run --commonownership transaction-hex
2. command for all heuristics (transaction analysis)
3. command for generating transaction template
*/
