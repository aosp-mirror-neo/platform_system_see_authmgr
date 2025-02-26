// Copyright 2025 Google LLC
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

//! Data structures used in AuthMgr Backend
use crate::{
    am_err,
    error::{Error, ErrorCode},
};
use alloc::{string::String, vec::Vec};
use authgraph_core::key::{CertChain, EcVerifyKey, InstanceIdentifier, Policy};
use authmgr_common::signed_connection_request::TransportID;

/// Version of the data structure format used to store details of a persistent instance
pub const VERSION_PERSISTENT_INSTANCE_CONTEXT: i32 = 1;
/// Version of the data structure format used to store details of a persistent client
pub const VERSION_PERSISTENT_CLIENT_CONTEXT: i32 = 1;
/// Version of the data structure format used to store details of a non persistent instance
pub const VERSION_NON_PERSISTENT_INSTANCE_CONTEXT: i32 = 1;
/// Version of the data structure format used to store details of a non persistent client
pub const VERSION_NON_PERSISTENT_CLIENT_CONTEXT: i32 = 1;

/// Type alias for a client identifier of 64 bytes. This identifier is assigned by the pVM.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ClientId(pub Vec<u8>);

/// Information stored in an authenticated connection established between a pVM and the AuthMgr BE.
/// This information is re-used when serving multiple requests for authorizing the
/// clients in the pVM
pub struct AuthenticatedConnectionState {
    /// Instance id of the pvm
    pub instance_id: InstanceIdentifier,
    /// Transport id of the pvm
    pub transport_id: TransportID,
    /// Unique sequence number assigned to the instance by the AuthMgr BE
    pub instance_seq_number: i32,
    /// DICE artifacts of the pvm
    pub dice_artifacts: DiceArtifacts,
    /// Public key of the signing key pair of the pvm
    pub pub_signing_key: EcVerifyKey,
    /// Whether the pvm is persistent
    pub is_persistent: bool,
    /// Maximum number of clients allowed for the pvm
    pub max_num_of_clients: usize,
    /// Cache of the authorized clients of the pvm
    pub authorized_clients: Vec<AuthorizedClient>,
}

impl AuthenticatedConnectionState {
    /// Populate the information to be stored in-memory in the connection state
    pub fn new(
        instance_id: InstanceIdentifier,
        transport_id: TransportID,
        instance_seq_number: i32,
        dice_artifacts: DiceArtifacts,
        pub_signing_key: EcVerifyKey,
        is_persistent: bool,
        max_num_of_clients: usize,
    ) -> Result<Self, Error> {
        let mut authorized_clients = Vec::<AuthorizedClient>::new();
        authorized_clients.try_reserve(max_num_of_clients)?;
        Ok(Self {
            instance_id,
            transport_id,
            instance_seq_number,
            dice_artifacts,
            pub_signing_key,
            is_persistent,
            max_num_of_clients,
            authorized_clients,
        })
    }

    /// Given the client id, get the id information of the corresponding authorized client.
    pub fn get_mutable_authorized_client(
        &mut self,
        client_id: &ClientId,
    ) -> Option<&mut AuthorizedClient> {
        self.authorized_clients.iter_mut().find(|client| client.client_id == *client_id)
    }

    /// Insert the authorized client into into the cache
    pub fn insert_authorized_client(
        &mut self,
        authorized_client: AuthorizedClient,
    ) -> Result<(), Error> {
        if self
            .authorized_clients
            .iter()
            .any(|client| client.sequence_number == authorized_client.sequence_number)
        {
            return Err(am_err!(
                InternalError,
                "a client with the given sequence number already exist in the cache"
            ));
        }
        if self.authorized_clients.len() == self.max_num_of_clients {
            return Err(am_err!(
                MemoryAllocationFailed,
                "Max limit for the authorized clients per connection reached."
            ));
        }
        self.authorized_clients.push(authorized_client);
        Ok(())
    }
}

/// Encapsulation of the DICE certificate chain and the DICE policy used to validate it
#[derive(Clone)]
pub struct DiceArtifacts {
    /// DICE certificate chain
    pub cert_chain: CertChain,
    /// DICE poicy
    pub policy: Policy,
}

/// Information associated with an authorized client. This information is used to check for
/// duplicate authorization attempts for the same client.
#[derive(Clone)]
pub struct AuthorizedClient {
    /// Client id
    pub client_id: ClientId,
    /// Unique sequence number assigned to the client by the AuthMgr BE
    pub sequence_number: i32,
    /// DICE policy of the client
    pub policy: Policy,
    /// A list of services that the client has connected to, which need to be notified upon client
    /// deletion.
    pub connected_services: Vec<String>,
}
