// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use tokio::time::{sleep, Duration};

use dusk_wallet::Error;
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
    status: fn(&str),
}

// helper structs to deserialize response
#[derive(Deserialize)]
struct Tx {
    pub txerror: String,
}
#[derive(Deserialize)]
struct Transactions {
    pub transactions: Vec<Tx>,
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
    pub fn new<S>(url: S, status: fn(&str)) -> Self
    where
        S: Into<String>,
    {
        Self {
            url: url.into(),
            status,
        }
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
                    );
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
