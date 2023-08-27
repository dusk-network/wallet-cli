// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

mod node;
mod prover;
mod storage;
mod wasm;

#[tokio::test]
async fn balance() {
    let mut wallet = wasm::wallet(0xbeef);

    let bal = wallet.sync().await.unwrap().balance;
    assert_eq!(bal, 0);

    let psk = wallet.public_spend_keys().await.unwrap()[0].clone();
    wallet.node.mint(&psk, 100).await.unwrap();

    let bal = wallet.sync().await.unwrap().balance;
    assert_eq!(bal, 100);

    let dead_key =
        wasm::wallet(0xdead).public_spend_keys().await.unwrap()[0].clone();

    let gas_limit = 30;
    let gas_price = 1;
    let r#type = "Obfuscated";
    let receiver = dead_key.clone();
    let ref_id = 37;
    let value = 25;
    wallet
        .transfer(gas_limit, gas_price, r#type, receiver, ref_id, value, &psk)
        .await
        .unwrap();

    let bal = wallet.sync().await.unwrap().balance;
    assert_eq!(bal, 45);

    let contract = "6npDLZTYYKjWbikdWfdCK2jDbUpPqQvaS9KPCBCvN3Ab";
    let method = "calculate";
    let payload = b"A great wind is blowing, and that gives you either imagination or a headache.";
    let crossover = Some(9);
    let gas_limit = 11;
    let gas_price = 2;
    wallet
        .call(
            contract, method, payload, crossover, gas_limit, gas_price, &psk,
        )
        .await
        .unwrap();

    let bal = wallet.sync().await.unwrap().balance;
    assert_eq!(bal, 14);

    let gas_limit = 3;
    let gas_price = 1;
    let r#type = "Transparent";
    let receiver = dead_key.clone();
    let ref_id = 38;
    let value = 6;
    wallet
        .transfer(gas_limit, gas_price, r#type, receiver, ref_id, value, &psk)
        .await
        .unwrap();

    let bal = wallet.sync().await.unwrap().balance;
    assert_eq!(bal, 5);

    let gas_limit = 1;
    let gas_price = 1;
    let r#type = "Transparent";
    let receiver = dead_key;
    let ref_id = 39;
    let value = 5;
    let result = wallet
        .transfer(gas_limit, gas_price, r#type, receiver, ref_id, value, &psk)
        .await;
    assert!(result.is_err());
}
