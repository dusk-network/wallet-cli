// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use base64::DecodeError;
use dusk_wallet_core::Transaction;
use tokio::time::{sleep, Duration};

use dusk_wallet::{Error, Status};
use gql_client::{Client, GraphQLErrorMessage};
use serde::Deserialize;
use serde_json::Value;

/// GraphQL is a helper struct that aggregates all queries done
/// to the Dusk GraphQL database.
/// This helps avoid having helper structs and boilerplate code
/// mixed with the wallet logic.
#[derive(Clone)]
pub struct GraphQL {
    url: String,
    status: Status,
}

// helper structs to deserialize response
#[derive(Deserialize, Debug)]
struct Tx {
    pub txerror: String,
    pub raw: Option<String>,
    pub gasspent: Option<u64>,
}

#[derive(Deserialize, Debug)]
struct Transactions {
    pub transactions: Vec<Tx>,
}

#[derive(Deserialize)]
struct Blocks {
    pub blocks: Vec<Transactions>,
}

/// Transaction status
#[derive(Debug)]
pub enum TxStatus {
    Ok,
    NotFound,
    Error(String),
}

fn is_database_error(json: &[GraphQLErrorMessage]) -> bool {
    // we stringify the json and use String.contains()
    // because GraphQLErrorMessage fields are private
    format!("{:?}", json[0]).contains("database: transaction not found")
}

impl GraphQL {
    /// Create a new GraphQL wallet client
    pub fn new<S>(url: S, status: Status) -> Result<Self, Error>
    where
        S: Into<String>,
    {
        Ok(Self {
            url: url.into(),
            status,
        })
    }

    /// Wait for a transaction to be confirmed (included in a block)
    pub async fn wait_for(&self, tx_id: &str) -> anyhow::Result<()> {
        const TIMEOUT_SECS: i32 = 30;
        let mut i = 1;
        while i <= TIMEOUT_SECS {
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
                    )?;
                    sleep(Duration::from_millis(1000)).await;
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
        // graphql connection
        let client = Client::new(&self.url);

        let query =
            "{transactions(txid:\"####\"){ txerror }}".replace("####", tx_id);

        let response = client.query::<Transactions>(&query).await;

        match response {
            Ok(Some(txs)) if txs.transactions.is_empty() => {
                Ok(TxStatus::NotFound)
            }
            Ok(Some(txs)) if txs.transactions[0].txerror.is_empty() => {
                Ok(TxStatus::Ok)
            }
            Ok(Some(txs)) => {
                let tx = &txs.transactions[0];
                let err_str = tx.txerror.as_str();
                let tx_err = serde_json::from_str::<Value>(err_str);

                let err = match tx_err {
                    Ok(data) => data["data"]
                        .as_str()
                        .map(|msg| msg.to_string())
                        .unwrap_or_else(|| err_str.to_string()),
                    Err(err) => err.to_string(),
                };

                Ok(TxStatus::Error(err))
            }
            Ok(None) => Err(GraphQLError::TxStatus),
            Err(err) => match err.json() {
                Some(json) if is_database_error(&json) => {
                    Ok(TxStatus::NotFound)
                }
                _ => Err(GraphQLError::Generic(err)),
            },
        }
    }

    /// Obtain transactions inside a block
    pub async fn txs_for_block(
        &self,
        block_height: u64,
    ) -> anyhow::Result<Vec<(Transaction, Option<u64>)>> {
        // graphql connection
        let client = Client::new(&self.url);

        let query =
            "{blocks(height:####){transactions{ txerror,raw,txid,gasspent }}}"
                .replace("####", block_height.to_string().as_str());

        let response = client.query::<Blocks>(&query).await;
        match response {
            Ok(Some(txs)) if txs.blocks.is_empty() => Ok(vec![]),
            Ok(Some(txs)) if txs.blocks[0].transactions.is_empty() => {
                Ok(vec![])
            }
            Ok(Some(txs)) => {
                if let Some(block) = txs.blocks.first().take() {
                    let tx: Option<
                        Result<Result<_, dusk_bytes::Error>, DecodeError>,
                    > = block
                        .transactions
                        .iter()
                        .map(|t| {
                            t.raw.as_ref().map(|raw| {
                                base64::decode(raw).map(|decoded| {
                                    Transaction::from_slice(&decoded)
                                        .map(|tx| (tx, t.gasspent))
                                })
                            })
                        })
                        .collect();

                    let tx = tx
                        .ok_or_else(|| {
                            Error::Transaction(
                                "No transactions found in block".to_string(),
                            )
                        })??
                        .map_err(Error::Bytes)?;

                    Ok(tx)
                } else {
                    Err(Error::Transaction(
                        "Cannot retreve first block".to_string(),
                    )
                    .into())
                }
            }
            Ok(None) => Err(GraphQLError::TxStatus.into()),
            Err(err) => Err(GraphQLError::Generic(err).into()),
        }
    }
}

/// Errors generated from GraphQL
#[derive(Debug, thiserror::Error)]
pub enum GraphQLError {
    /// Generic errors
    #[error("Error fetching data from the node: {0}")]
    Generic(gql_client::GraphQLError),
    /// Failed to fetch transaction status
    #[error("Failed to obtain transaction status")]
    TxStatus,
}

impl From<gql_client::GraphQLError> for GraphQLError {
    fn from(e: gql_client::GraphQLError) -> Self {
        Self::Generic(e)
    }
}

#[ignore = "Leave it here just for manual tests"]
#[tokio::test]
async fn test() -> Result<(), Box<dyn std::error::Error>> {
    let gql = GraphQL {
        status: |s| Ok(println!("{s}")),
        url: "http://nodes.dusk.network:9500/graphql".to_string(),
    };
    let _ = gql
        .tx_status(
            "dbc5a2c949516ecfb418406909d195c3cc267b46bd966a3ca9d66d2e13c47003",
        )
        .await?;
    let r = gql.txs_for_block(90).await?;
    r.iter().for_each(|(t, _)| {
        let txh = format!("{:x}", t.hash());
        println!("txid: {}", txh);
        // let raw = base64::decode(&t.raw.as_ref().unwrap()).unwrap();
        // let tx = Transaction::from_slice(&raw);
    });
    Ok(())
}
