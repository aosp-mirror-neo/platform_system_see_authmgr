// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

//! Tests for the core functionality of the AuthMgr BE.
//! This module defines structs that represent a pvm instance and a client in order to imitate an
//! AuthMgr FE in these tests. It also provides mock implementations for the *Connection traits that
//! should be tightly coupled with an actual AuthMgr BE TA running in TEE.
//! The generic tests provided by this module can be used to test the end to end AuthMgr protocol
//! with any implementation of the other three main traits of AuthMgr (Crypto, Device and *Storage),
//! that can be implemented fairly independent of an AuthMgr BE TA running in TEE.
use authgraph_core::key::{CertChain, DiceChainEntry, EcSignKey, Policy};
use authgraph_core::traits::{EcDsa, Rng};
use authmgr_be::authorization::AuthMgrBE;
use authmgr_be::data_structures::{AuthenticatedConnectionState, ClientId};
use authmgr_be::error::Error;
use authmgr_be::traits::{RawConnection, RpcConnection};
use authmgr_common::{
    signed_connection_request::{
        Challenge, ConnectionRequest, TransportID, TEMP_AUTHMGR_BE_TRANSPORT_ID,
    },
    Result as AuthMgrCommonResult, Token, TOKEN_LENGTH,
};
use coset::CborSerializable;

/// Struct that represents a pvm instance for testing purposes
pub struct PVM {
    /// The connection from pvm to AuthMgr
    pub rpc_connection: RpcConnectionInfo,
    /// Set of clients to be authorized
    pub clients: Vec<Client>,
    /// DICE certificate chain of the pvm
    pub dice_chain: CertChain,
    /// DICE policy of the pvm
    pub dice_chain_policy: Policy,
    /// Signing key that originates from the DICE CDI
    pub sign_key: EcSignKey,
    /// Implementation of the EcDsa trait
    pub ecdsa: Box<dyn EcDsa>,
    /// Implementation of the Rng trait
    pub rng: Box<dyn Rng>,
}

impl PVM {
    /// Constructor
    pub fn new(
        dice_chain: CertChain,
        dice_chain_policy: Policy,
        sign_key: EcSignKey,
        ecdsa: Box<dyn EcDsa>,
        rng: Box<dyn Rng>,
        transport_id: TransportID,
    ) -> Self {
        Self {
            rpc_connection: RpcConnectionInfo::new(transport_id),
            clients: Vec::<Client>::new(),
            dice_chain,
            dice_chain_policy,
            sign_key,
            ecdsa,
            rng,
        }
    }

    /// Add a client to the pvm instance
    pub fn add_client(&mut self, client: Client) {
        self.clients.push(client);
    }

    /// Given the challenge returned by the AuthMgr-BE, sign the connection request.
    pub fn sign_connection_request(&self, challenge: Challenge) -> AuthMgrCommonResult<Vec<u8>> {
        let conn_req = ConnectionRequest::new_for_ffa_transport(
            challenge,
            self.rpc_connection.transport_id,
            TEMP_AUTHMGR_BE_TRANSPORT_ID,
        );
        conn_req.sign(&self.sign_key, &*self.ecdsa, self.sign_key.get_cose_sign_algorithm())
    }

    /// Create a new connection and a token for a client
    pub fn create_connection_and_token_for_client(&self) -> (RawConnectionInfo, Token) {
        let mut token = [0u8; TOKEN_LENGTH];
        self.rng.fill_bytes(&mut token);
        (
            RawConnectionInfo::new(
                self.rpc_connection.transport_id,
                0, /*This is N/A for the mock implementation*/
            ),
            token,
        )
    }
}

/// Struct that represents a client TA in a pvm instance for testing purposes
pub struct Client {
    /// DICE leaf certificate of the client
    pub dice_leaf: DiceChainEntry,
    /// DICE policy of the client
    pub dice_leaf_policy: Policy,
    /// Client id
    pub client_id: ClientId,
    /// Name of the services that the client needs to connect to
    pub services: Vec<String>,
}

impl Client {
    /// Constructor
    pub fn new(
        dice_leaf: DiceChainEntry,
        dice_leaf_policy: Policy,
        services: Vec<String>,
        rng: Box<dyn Rng>,
    ) -> Self {
        let mut client_id_bytes = [0u8; 32];
        rng.fill_bytes(&mut client_id_bytes);
        Self {
            dice_leaf,
            dice_leaf_policy,
            client_id: ClientId(client_id_bytes.to_vec()),
            services,
        }
    }
}

/// Implementation of the `RpcConnection` trait
pub struct RpcConnectionInfo {
    /// Transport ID (a.k.a VM ID)
    pub transport_id: TransportID,
    /// Conncection state to be stored by the AuthMgr protocol
    pub connection_state: Option<AuthenticatedConnectionState>,
}

impl RpcConnectionInfo {
    /// Constructor
    pub fn new(transport_id: TransportID) -> Self {
        Self { transport_id, connection_state: None }
    }
}

impl RpcConnection for RpcConnectionInfo {
    /// Return the transport ID of the instance that is on the other end of the connection
    fn get_peer_transport_id(&self) -> Result<TransportID, Error> {
        Ok(self.transport_id)
    }

    /// Store the re-usable information in the connection state to be used while serving multiple
    /// client authorization requests from the same pVM instance
    fn store_authenticated_state(
        &mut self,
        connection_state: AuthenticatedConnectionState,
    ) -> Result<(), Error> {
        self.connection_state = Some(connection_state);
        Ok(())
    }

    /// Return the state if the state has been stored for this connecction. Since the state is
    /// stored only after the peer on the other side of the connection is authenticated, the
    /// existence of a connection state is also an indication that the connection is authenticated.
    fn get_authenticated_state(&self) -> Result<Option<&AuthenticatedConnectionState>, Error> {
        Ok(self.connection_state.as_ref())
    }

    /// Return the mutable state if the state has been stored for this connecction. Since the state
    /// is stored only after the peer on the other side of the connection is authenticated, the
    /// existence of a connection state is also an indication that the connection is authenticated.
    fn get_mutable_authenticated_state(
        &mut self,
    ) -> Result<Option<&mut AuthenticatedConnectionState>, Error> {
        Ok(self.connection_state.as_mut())
    }

    /// Delete the state stored associated with the connection. This is called when the connection
    /// is closed.
    fn remove_authenticated_state(&mut self) -> Result<(), Error> {
        self.connection_state = None;
        Ok(())
    }
}

/// Implementation of the `RawConnection` trait
pub struct RawConnectionInfo {
    /// Transport ID (a.k.a VM ID)
    transport_id: TransportID,
    /// Raw file descriptor corresponding to this connection.
    raw_fd: i32,
}

impl RawConnectionInfo {
    /// Constructor
    pub fn new(transport_id: TransportID, raw_fd: i32) -> Self {
        Self { transport_id, raw_fd }
    }
}

impl RawConnection for RawConnectionInfo {
    /// Return the transport ID of the instance that is on the other end of the connection
    fn get_peer_transport_id(&self) -> Result<TransportID, Error> {
        Ok(self.transport_id)
    }

    /// Return the raw file descriptor id of the underlying connection. This method is not called by
    /// the authmgr backend core library. Rather, this is added for use of the vendor
    /// implementations which pass in an implementation of `RawConnection` trait into this library
    /// and then retrieve it back in their implementations.
    fn into_raw_fd(self: Box<Self>) -> i32 {
        // Note: in the actual implementation, we need to make sure that the object is not destoyed
        // at the end of this method
        self.raw_fd
    }
}

/// Test the happy path for the full AuthMgr protocol with a single pvm instance.
pub fn test_auth_mgr_protocol_succeeds_single_pvm(authmgr_be: &mut AuthMgrBE, mut pvm: PVM) {
    let challenge: Challenge = authmgr_be
        .init_authentication(
            &pvm.rpc_connection,
            &pvm.dice_chain.clone().to_vec().expect("error in encoding the DICE chain"),
            None,
        )
        .expect("init_auth failed");
    let signature =
        pvm.sign_connection_request(challenge).expect("signing connection request failed");
    authmgr_be
        .complete_authentication(&mut pvm.rpc_connection, &signature, &pvm.dice_chain_policy.0)
        .expect("complete_auth failed");
    for client in &pvm.clients {
        for service in &client.services {
            let (conn, token) = pvm.create_connection_and_token_for_client();
            authmgr_be
                .init_connection_for_client(Box::new(conn), token)
                .expect("init_connection_for_client failed");
            authmgr_be
                .authorize_and_connect_client_to_trusted_service(
                    &mut pvm.rpc_connection,
                    &client.client_id.0,
                    service,
                    token,
                    &client.dice_leaf.clone().to_vec().expect("error in encoding the DICE cert"),
                    &client.dice_leaf_policy.0,
                )
                .expect("authorize_and_connect_client_to_trusted_service failed");
        }
    }
}
