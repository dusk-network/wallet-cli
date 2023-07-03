// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#[cfg(not(windows))]
use tokio::net::UnixStream;
#[cfg(not(windows))]
use tonic::transport::Uri;
#[cfg(not(windows))]
use tower::service_fn;

use async_trait::async_trait;
use std::str::FromStr;

use tonic::codegen::InterceptedService;
use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::transport::{Channel, Endpoint};
use tonic::Status;

use rusk_schema::network_client::NetworkClient as GrpcNetworkClient;
use rusk_schema::prover_client::ProverClient as GrpcProverClient;
use rusk_schema::state_client::StateClient as GrpcStateClient;

use crate::error::Error;
use anyhow::Result;

/// Supported Rusk version
const REQUIRED_RUSK_VERSION: &str = "0.6.0";

/// Rusk service clients all include versioning middleware
pub(crate) type RuskNetworkClient =
    GrpcNetworkClient<InterceptedService<Channel, RuskVersionInterceptor>>;
pub(crate) type RuskStateClient =
    GrpcStateClient<InterceptedService<Channel, RuskVersionInterceptor>>;
pub(crate) type RuskProverClient =
    GrpcProverClient<InterceptedService<Channel, RuskVersionInterceptor>>;

/// Clients to Rusk services
pub(crate) struct RuskClient {
    pub network: RuskNetworkClient,
    pub state: RuskStateClient,
    pub prover: RuskProverClient,
}

impl RuskClient {
    /// Attempts a connection to the network and, if successful,
    /// returns a connected `RuskClient` instance
    pub async fn connect<E>(endpoint: E) -> Result<Self, Error>
    where
        E: RuskEndpoint,
    {
        let rusk = Self {
            network: GrpcNetworkClient::with_interceptor(
                endpoint.state().await?,
                RuskVersionInterceptor,
            ),
            state: GrpcStateClient::with_interceptor(
                endpoint.state().await?,
                RuskVersionInterceptor,
            ),
            prover: GrpcProverClient::with_interceptor(
                endpoint.prover().await?,
                RuskVersionInterceptor,
            ),
        };

        Ok(rusk)
    }
}

/// Adds the compatible Rusk version in every request's gRPC headers
#[derive(Clone)]
pub struct RuskVersionInterceptor;

impl Interceptor for RuskVersionInterceptor {
    fn call(
        &mut self,
        mut request: tonic::Request<()>,
    ) -> Result<tonic::Request<()>, Status> {
        // add `x-rusk-version` to header metadata
        let md = request.metadata_mut();
        md.append(
            "x-rusk-version",
            MetadataValue::from_static(REQUIRED_RUSK_VERSION),
        );
        Ok(request)
    }
}

/// Transport details for the Dusk Network
#[async_trait]
pub trait RuskEndpoint {
    /// Returns the [Channel] used to communicate with the state server
    async fn state(&self) -> Result<Channel, Error>;
    /// Returns the [Channel] used to communicate with the prover server
    async fn prover(&self) -> Result<Channel, Error>;
}

/// Transport details for establishing a TCP/IP connection
/// to the Dusk Network
#[derive(Debug)]
pub struct TransportTCP {
    rusk_addr: String,
    prov_addr: String,
}

impl TransportTCP {
    /// Creates a new TCP IP transport with the given addresses for the state
    /// and the prover
    pub fn new<S>(rusk_addr: S, prov_addr: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            rusk_addr: rusk_addr.into(),
            prov_addr: prov_addr.into(),
        }
    }
}

#[async_trait]
impl RuskEndpoint for TransportTCP {
    async fn state(&self) -> Result<Channel, Error> {
        Ok(Endpoint::from_str(&self.rusk_addr)?.connect().await?)
    }

    async fn prover(&self) -> Result<Channel, Error> {
        Ok(Endpoint::from_str(&self.prov_addr)?.connect().await?)
    }
}

/// Transport details for establishing a unix-domain socket (UDS)
/// connection to a local Rusk instance
pub struct TransportUDS {
    addr: String,
}

impl TransportUDS {
    /// Creates a new UDS transport with the given address.
    pub fn new<S>(path: S) -> Self
    where
        S: Into<String>,
    {
        Self { addr: path.into() }
    }
}

#[async_trait]
impl RuskEndpoint for TransportUDS {
    #[cfg(not(windows))]
    async fn state(&self) -> Result<Channel, Error> {
        let addr = self.addr.clone();
        Ok(Endpoint::try_from("http://[::]:50051")
            .expect("parse address")
            .connect_with_connector(service_fn(move |_: Uri| {
                let path = (addr[..]).to_string();
                UnixStream::connect(path)
            }))
            .await?)
    }

    #[cfg(windows)]
    async fn state(&self) -> Result<Channel, Error> {
        Err(Error::SocketsNotSupported(self.addr.clone()))
    }

    async fn prover(&self) -> Result<Channel, Error> {
        self.state().await
    }
}
