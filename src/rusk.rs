// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::str::FromStr;

use tonic::codegen::InterceptedService;
use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::transport::{Channel, Endpoint};
use tonic::Status;

use rusk_schema::network_client::NetworkClient as GrpcNetworkClient;
use rusk_schema::prover_client::ProverClient as GrpcProverClient;
use rusk_schema::state_client::StateClient as GrpcStateClient;

#[cfg(not(windows))]
use tokio::net::UnixStream;
#[cfg(not(windows))]
use tonic::transport::Uri;
#[cfg(not(windows))]
use tower::service_fn;

use crate::Error;

/// Supported Rusk version
const REQUIRED_RUSK_VERSION: &str = "0.5.0-rc.0";

/// Rusk service clients all include versioning middleware
pub(crate) type RuskNetworkClient =
    GrpcNetworkClient<InterceptedService<Channel, RuskVersionInterceptor>>;
pub(crate) type RuskStateClient =
    GrpcStateClient<InterceptedService<Channel, RuskVersionInterceptor>>;
pub(crate) type RuskProverClient =
    GrpcProverClient<InterceptedService<Channel, RuskVersionInterceptor>>;

/// Clients to Rusk services
pub struct RuskClient {
    pub network: RuskNetworkClient,
    pub state: RuskStateClient,
    pub prover: RuskProverClient,
}

impl RuskClient {
    /// Creates a `Rusk` instance and attempts to connect
    /// all clients via TCP.
    pub async fn with_tcp(
        rusk_addr: &str,
        prov_addr: &str,
    ) -> Result<RuskClient, Error> {
        let rusk_chan = Endpoint::from_str(rusk_addr)?
            .connect()
            .await
            .map_err(Error::RuskConn)?;
        let prov_chan = Endpoint::from_str(prov_addr)?
            .connect()
            .await
            .map_err(Error::RuskConn)?;

        Ok(RuskClient {
            network: GrpcNetworkClient::with_interceptor(
                rusk_chan.clone(),
                RuskVersionInterceptor,
            ),
            state: GrpcStateClient::with_interceptor(
                rusk_chan,
                RuskVersionInterceptor,
            ),
            prover: GrpcProverClient::with_interceptor(
                prov_chan,
                RuskVersionInterceptor,
            ),
        })
    }

    /// Creates a `Rusk` instance and attempts to connect
    /// all clients via UDS (unix domain sockets).
    #[cfg(not(windows))]
    pub async fn with_uds(socket_path: &str) -> Result<RuskClient, Error> {
        let socket_path = socket_path.to_string();
        let channel = Endpoint::try_from("http://[::]:50051")
            .expect("parse address")
            .connect_with_connector(service_fn(move |_: Uri| {
                let path = (&socket_path[..]).to_string();
                UnixStream::connect(path)
            }))
            .await?;

        Ok(RuskClient {
            network: GrpcNetworkClient::with_interceptor(
                channel.clone(),
                RuskVersionInterceptor,
            ),
            state: GrpcStateClient::with_interceptor(
                channel.clone(),
                RuskVersionInterceptor,
            ),
            prover: GrpcProverClient::with_interceptor(
                channel,
                RuskVersionInterceptor,
            ),
        })
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
