// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_wallet_core::Transaction;
use tokio::time::{sleep, Duration};

use dusk_wallet::{Error, RuskHttpClient, RuskRequest};
use serde::Deserialize;

/// GraphQL is a helper struct that aggregates all queries done
/// to the Dusk GraphQL database.
/// This helps avoid having helper structs and boilerplate code
/// mixed with the wallet logic.
#[derive(Clone)]
pub struct GraphQL {
    client: RuskHttpClient,
    status: fn(&str),
}

// helper structs to deserialize response
#[derive(Deserialize)]
struct SpentTx {
    pub err: Option<String>,
    #[serde(alias = "gasSpent", default)]
    pub gas_spent: f64,
}

#[derive(Deserialize)]
struct Tx {
    pub id: String,
    #[serde(default)]
    pub raw: String,
}
#[derive(Deserialize)]
struct Block {
    pub transactions: Vec<Tx>,
}

#[derive(Deserialize)]
struct BlockResponse {
    pub block: Option<Block>,
}

#[derive(Deserialize)]
struct SpentTxResponse {
    pub tx: Option<SpentTx>,
}

/// Transaction status
#[derive(Debug)]
pub enum TxStatus {
    Ok,
    NotFound,
    Error(String),
}

impl GraphQL {
    /// Create a new GraphQL wallet client
    pub fn new<S>(url: S, status: fn(&str)) -> Self
    where
        S: Into<String>,
    {
        Self {
            client: RuskHttpClient::new(url.into()),
            status,
        }
    }

    /// Wait for a transaction to be confirmed (included in a block)
    pub async fn wait_for(&self, tx_id: &str) -> anyhow::Result<()> {
        const TIMEOUT_SECS: i32 = 100;
        let mut i = 1;
        while true {
            let status = self.tx_status(tx_id).await?;

            match status {
                TxStatus::Ok => break,
                TxStatus::Error(err) => return Err(Error::Transaction(err))?,
                TxStatus::NotFound => {
                    (self.status)(
                        format!(
                            "Waiting for confirmation... ({}/{})",
                            i, TIMEOUT_SECS
                        )
                        .as_str(),
                    );
                    sleep(Duration::from_millis(5000)).await;
                    i += 1;
                }
            }
        }
        Ok(())
    }

    /// Obtain transaction status
    async fn tx_status(
        &self,
        tx_id: &str,
    ) -> anyhow::Result<TxStatus, GraphQLError> {
        let query =
            "query { tx(hash: \"####\") { err }}".replace("####", tx_id);
        let response = self.query(&query).await?;
        let response = serde_json::from_slice::<SpentTxResponse>(&response)?.tx;

        match response {
            Some(SpentTx { err: Some(err), .. }) => Ok(TxStatus::Error(err)),
            Some(_) => Ok(TxStatus::Ok),
            None => Ok(TxStatus::NotFound),
        }
    }

    /// Obtain transactions inside a block
    pub async fn txs_for_block(
        &self,
        block_height: u64,
    ) -> anyhow::Result<Vec<(Transaction, u64)>, GraphQLError> {
        let query = "query { block(height: ####) { transactions {id, raw}}}"
            .replace("####", block_height.to_string().as_str());

        let response = self.query(&query).await?;
        let response =
            serde_json::from_slice::<BlockResponse>(&response)?.block;
        let block = response.ok_or(GraphQLError::BlockInfo)?;
        let mut ret = vec![];

        for tx in block.transactions {
            let tx_raw =
                hex::decode(&tx.raw).map_err(|_| GraphQLError::TxStatus)?;
            let ph_tx = Transaction::from_slice(&tx_raw).unwrap();
            let query = "query { tx(hash: \"####\") { gasSpent, err }}"
                .replace("####", &tx.id);
            let response = self.query(&query).await?;
            let response =
                serde_json::from_slice::<SpentTxResponse>(&response)?.tx;
            let spent_tx = response.ok_or(GraphQLError::TxStatus)?;
            ret.push((ph_tx, spent_tx.gas_spent as u64));
        }
        Ok(ret)
    }
}

/// Errors generated from GraphQL
#[derive(Debug, thiserror::Error)]
pub enum GraphQLError {
    /// Generic errors
    #[error("Error fetching data from the node: {0}")]
    Generic(dusk_wallet::Error),
    /// Failed to fetch transaction status
    #[error("Failed to obtain transaction status")]
    TxStatus,
    #[error("Failed to obtain block info")]
    BlockInfo,
}

impl From<dusk_wallet::Error> for GraphQLError {
    fn from(e: dusk_wallet::Error) -> Self {
        Self::Generic(e)
    }
}

impl From<serde_json::Error> for GraphQLError {
    fn from(e: serde_json::Error) -> Self {
        Self::Generic(e.into())
    }
}

impl GraphQL {
    pub async fn query(
        &self,
        query: &str,
    ) -> Result<Vec<u8>, dusk_wallet::Error> {
        let request = RuskRequest::new("gql", query.as_bytes().to_vec());
        self.client.call(2, "Chain", &request).await
    }
}

#[ignore = "Leave it here just for manual tests"]
#[tokio::test]
async fn test() -> Result<(), Box<dyn std::error::Error>> {
    let gql = GraphQL {
        status: |s| {
            println!("{s}");
        },
        client: RuskHttpClient::new(
            "http://nodes.dusk.network:9500/graphql".to_string(),
        ),
    };
    let _ = gql
        .tx_status(
            "dbc5a2c949516ecfb418406909d195c3cc267b46bd966a3ca9d66d2e13c47003",
        )
        .await?;
    let block_txs = gql.txs_for_block(90).await?;
    block_txs.iter().for_each(|(t, _)| {
        let hash = rusk_abi::hash::Hasher::digest(t.to_hash_input_bytes());
        let tx_id = hex::encode(hash.to_bytes());
        println!("txid: {tx_id}");
    });
    Ok(())
}

#[tokio::test]
async fn deser() -> Result<(), Box<dyn std::error::Error>> {
    let block_not_found = r#"{"block":null}"#;
    serde_json::from_str::<BlockResponse>(block_not_found).unwrap();

    let block_without_tx = r#"{"block":{"transactions":[]}}"#;
    serde_json::from_str::<BlockResponse>(block_without_tx).unwrap();

    let block_with_tx = r#"{"block":{"transactions":[{"id":"88e6804989cc2f3fd5bf94dcd39a4e7b7da9a1114d9b8bf4e0515264bc81c50f"}]}}"#;
    serde_json::from_str::<BlockResponse>(block_with_tx).unwrap();

    Ok(())
}
