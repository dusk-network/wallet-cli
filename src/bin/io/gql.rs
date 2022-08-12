// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::fmt;

use tokio::time::{sleep, Duration};

use crate::Error;
use gql_client::Client;
use serde::Deserialize;
use serde_json::Value;

/// GraphQL is a helper struct that aggregates all queries done
/// to the Dusk GraphQL database.
/// This helps avoid having helper structs and boilerplate code
/// mixed with the wallet logic
#[derive(Clone)]
pub struct GraphQL {
    url: String,
    status: fn(&str),
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
            url: url.into(),
            status,
        }
    }

    /// Wait for a transaction to be confirmed (included in a block)
    pub async fn wait_for(&self, tx_id: &str) -> Result<(), Error> {
        const TIMEOUT_SECS: i32 = 30;
        let mut i = 1;
        while i <= TIMEOUT_SECS {
            let status = self.tx_status(tx_id).await?;
            match status {
                TxStatus::Ok => break,
                TxStatus::Error(err) => return Err(Error::Transaction(err)),
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
    async fn tx_status(&self, tx_id: &str) -> Result<TxStatus, GraphQLError> {
        // graphql connection
        let client = Client::new(&self.url);

        // helper structs to deserialize response
        #[derive(Deserialize)]
        struct Tx {
            pub txerror: String,
        }
        #[derive(Deserialize)]
        struct Transactions {
            pub transactions: Vec<Tx>,
        }

        let query =
            "{transactions(txid:\"####\"){ txerror }}".replace("####", tx_id);

        let response = client.query::<Transactions>(&query).await;

        // we're interested in different types of errors
        if response.is_err() {
            let err = response.err().unwrap();
            return match err.json() {
                Some(json) => {
                    // we stringify the json and use String.contains()
                    // because GraphQLErrorMessage fields are private
                    let json_str = format!("{:?}", json[0]);
                    if json_str.contains("database: transaction not found") {
                        Ok(TxStatus::NotFound)
                    } else {
                        Err(GraphQLError::Generic(err))
                    }
                }
                None => Err(GraphQLError::Generic(err)),
            };
        }

        // fetch and parse the response data
        let data = response.expect("GQL response failed");
        match data {
            Some(txs) => {
                if txs.transactions.is_empty() {
                    Ok(TxStatus::NotFound)
                } else {
                    let tx = &txs.transactions[0];
                    if tx.txerror.is_empty() {
                        Ok(TxStatus::Ok)
                    } else {
                        let err_str = tx.txerror.as_str();
                        let tx_err = serde_json::from_str::<Value>(err_str);
                        match tx_err {
                            Ok(data) => match data["data"].as_str() {
                                Some(msg) => {
                                    Ok(TxStatus::Error(msg.to_string()))
                                }
                                None => {
                                    Ok(TxStatus::Error(err_str.to_string()))
                                }
                            },
                            Err(err) => Ok(TxStatus::Error(err.to_string())),
                        }
                    }
                }
            }
            None => Err(GraphQLError::TxStatus),
        }
    }
}

/// Errors generated from GraphQL
pub enum GraphQLError {
    /// Generic errors
    Generic(gql_client::GraphQLError),
    /// Failed to fetch transaction status
    TxStatus,
}

impl From<gql_client::GraphQLError> for GraphQLError {
    fn from(e: gql_client::GraphQLError) -> Self {
        Self::Generic(e)
    }
}

impl fmt::Display for GraphQLError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            GraphQLError::Generic(err) => {
                write!(
                    f,
                    "Error fetching data from the node:\n{}\n{:#?}",
                    err.message(),
                    err.json()
                )
            }
            GraphQLError::TxStatus => {
                write!(f, "Failed to obtain transaction status")
            }
        }
    }
}

impl fmt::Debug for GraphQLError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            GraphQLError::Generic(err) => {
                write!(
                    f,
                    "Error fetching data from the node:\n{}\n{:#?}",
                    err.message(),
                    err.json()
                )
            }
            GraphQLError::TxStatus => {
                write!(f, "Failed to obtain transaction status")
            }
        }
    }
}
