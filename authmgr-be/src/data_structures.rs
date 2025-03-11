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
    traits::RawConnection,
};
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use authgraph_core::key::{CertChain, EcVerifyKey, InstanceIdentifier, Policy};
use authmgr_common::{
    signed_connection_request::{Challenge, TransportID},
    Token,
};
use log::warn;

/// Version of the data structure format used to store details of a persistent instance
pub const VERSION_PERSISTENT_INSTANCE_CONTEXT: i32 = 1;
/// Version of the data structure format used to store details of a persistent client
pub const VERSION_PERSISTENT_CLIENT_CONTEXT: i32 = 1;

/// Default value for maximum number of entries in the cache for authentication started pVMs
pub const MAX_SIZE_AUTH_STARTED_PVMS: usize = 6;
/// Default value for maximum number of entries in the cache for authenticated pVMs
pub const MAX_SIZE_AUTH_COMPLETED_PVMS: usize = 6;
/// Default value for the maximum number of entries in the cache for authorized clients
/// per connection
pub const MAX_AUTHORIZED_CLIENTS_PER_CONNECTION: usize = 8;

/// Type alias for a client identifier of 64 bytes. This identifier is assigned by the pVM.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ClientId(pub Vec<u8>);

/// Information stored in an authenticated connection established between a pVM and the AuthMgr BE.
/// This information is re-used when serving multiple requests for authorizing the
/// clients in the pVM
pub struct AuthenticatedConnectionState {
    /// Instance id of the pvm
    pub instance_id: Arc<InstanceIdentifier>,
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
        instance_id: Arc<InstanceIdentifier>,
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
        self.authorized_clients.iter_mut().find(|client| *client.client_id == *client_id)
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
    pub cert_chain: Arc<CertChain>,
    /// DICE poicy
    pub policy: Arc<Policy>,
}

/// Information associated with an authorized client. This information is used to check for
/// duplicate authorization attempts for the same client.
#[derive(Clone)]
pub struct AuthorizedClient {
    /// Client id
    pub client_id: Arc<ClientId>,
    /// Unique sequence number assigned to the client by the AuthMgr BE
    pub sequence_number: i32,
    /// DICE policy of the client
    pub policy: Arc<Policy>,
}

impl AuthorizedClient {
    /// Update the client's policy with the given policy
    pub fn update_policy(&mut self, updated_policy: &Arc<Policy>) {
        self.policy = Arc::clone(updated_policy);
    }
}

/// Information of a persistent pvm instance stored in the persistent secure storage.
/// Deletion of the persistent instances (and clients) at runtime is not currently supported.
#[derive(Clone)]
pub struct PersistentInstanceContext {
    /// Version of the data structure format
    pub version: i32,
    /// Unique sequence number of the persistent instance
    pub sequence_number: i32,
    /// DICE policy
    pub dice_policy: Arc<Policy>,
}

/// Information of a persistent client stored in the persistent secure storage.
#[derive(Clone)]
pub struct PersistentClientContext {
    /// Version of the data structure format
    pub version: i32,
    /// Unique sequence number of the persistent client
    pub sequence_number: i32,
    /// DICE policy
    pub dice_policy: Arc<Policy>,
}

/// Encapsulates information about a pVM instance which has completed step 1 of phase 1 of the
/// AuthMgr protocol  (i.e. `init_authentication`), but not step 2 (i.e. `complete_authentication`).
#[derive(Clone, PartialEq)]
pub struct AuthStartedPvm {
    /// Transport id of the pvm (a.k.a. VM ID)
    pub transport_id: TransportID,
    /// Instance id of the pvm
    pub instance_id: Arc<InstanceIdentifier>,
    /// Challenge issued by the AuthMgr BE to this pvm
    pub challenge: Challenge,
    /// Certificate chain of the pvm
    pub cert_chain: Arc<CertChain>,
}

impl AuthStartedPvm {
    /// Perform state transition of an AuthStartedPvm.
    pub fn mark_as_authenticated(
        &self,
        auth_started_pvms: &mut AuthStartedPvms,
        authenticated_pvms: &mut AuthenticatedPvms,
    ) -> Result<(), Error> {
        // Remove any other entries in `AuthStartedPvms` with the authenticated instance id, to
        // enforce the Trust On First Use (TOFU) principle.
        auth_started_pvms.remove_via_instance_id(&self.instance_id);
        authenticated_pvms.insert(self)
    }
}

/// A list of pVMs which have initiated authentication, but not have completed authentication.
pub struct AuthStartedPvms {
    /// The number of allowed authentication started pvms at a given time
    capacity: usize,
    /// The list of authentication started pvms
    auth_started_pvms: VecDeque<AuthStartedPvm>,
}

impl AuthStartedPvms {
    /// Constructor
    pub fn new(capacity: usize) -> Result<Self, Error> {
        let mut auth_started_pvms = VecDeque::new();
        auth_started_pvms.try_reserve(capacity)?;
        Ok(AuthStartedPvms { capacity, auth_started_pvms })
    }

    /// Insert a new entry to the list
    pub fn insert(&mut self, auth_started_pvm: AuthStartedPvm) {
        if self.auth_started_pvms.len() == self.capacity {
            // Here we remove the oldest entry instead of returning an error in order to prevent
            // genuine pvms from being denied from starting authentication due to `AuthStartedPvms`
            // being filled up to the capacity - which can be caused by both malicious activity and
            // non-malicious activity (e.g. a pvm starts authentication, but never completes).
            warn!("Maximum number of auth started pvms reached. Removing the oldest one.");
            self.auth_started_pvms.pop_front();
        }
        self.auth_started_pvms.push_back(auth_started_pvm);
    }

    /// Check if an entry with a given transport id already exists in the list - this is used to
    /// prevent duplicated authentication attempts from the same instance.
    pub fn has_transport_id(&self, transport_id: TransportID) -> bool {
        self.auth_started_pvms.iter().any(|entry| entry.transport_id == transport_id)
    }

    /// Take an entry out of the list via its transport id - this is used to retrieve the required
    /// information to perform step 2 of phase 1 for those who have performed step 1 of phase 1.
    pub fn take_via_transport_id(&mut self, transport_id: TransportID) -> Option<AuthStartedPvm> {
        let index =
            self.auth_started_pvms.iter().position(|entry| entry.transport_id == transport_id);
        index.map(|index| self.auth_started_pvms.remove(index))?
    }

    /// Remove an entry via its transport id - this is used to remove an entry when only the
    /// transport id is available - e.g. upon connection close.
    pub fn remove_via_transport_id(&mut self, transport_id: TransportID) {
        self.auth_started_pvms.retain(|entry| entry.transport_id != transport_id);
    }

    /// Remove all entries with a given instance id - this is used to remove all entries with
    /// an authenticated instance id.
    pub fn remove_via_instance_id(&mut self, instance_id: &InstanceIdentifier) {
        self.auth_started_pvms.retain(|entry| &*entry.instance_id != instance_id);
    }
}

/// Encapsulates information about a pVM instance which has completed phase 1 of the AuthMgr
/// protocol
#[derive(PartialEq)]
pub struct AuthenticatedPvm {
    /// Instance id of the pvm
    pub instance_id: Arc<InstanceIdentifier>,
    /// Transport id of the pvm
    pub transport_id: TransportID,
}

/// A list of pVMs which have completed authentication
pub struct AuthenticatedPvms {
    /// The number of allowed authentication completed pvms at a given time
    capacity: usize,
    /// List of authentication completed pvms
    authenticated_pvms: Vec<AuthenticatedPvm>,
}

impl AuthenticatedPvms {
    /// Constructor
    pub fn new(capacity: usize) -> Result<Self, Error> {
        let mut authenticated_pvms = Vec::<AuthenticatedPvm>::new();
        authenticated_pvms.try_reserve(capacity)?;
        Ok(AuthenticatedPvms { capacity, authenticated_pvms })
    }

    /// Insert a new entry to the list, constructed from the given AuthStartedPvm
    pub fn insert(&mut self, auth_started_pvm: &AuthStartedPvm) -> Result<(), Error> {
        if self.authenticated_pvms.len() == self.capacity {
            return Err(am_err!(
                MemoryAllocationFailed,
                "Maximum number of authenticated pvms reached."
            ));
        }
        let authenticated_pvm = AuthenticatedPvm {
            instance_id: Arc::clone(&auth_started_pvm.instance_id),
            transport_id: auth_started_pvm.transport_id,
        };
        self.authenticated_pvms.push(authenticated_pvm);
        Ok(())
    }

    /// Check if a pvm with a given instance id already exists in the list - this is used to prevent
    /// duplicated authentication attempts
    pub fn has_instance_id(&self, instance_id: &InstanceIdentifier) -> bool {
        self.authenticated_pvms.iter().any(|entry| &*entry.instance_id == instance_id)
    }

    /// Check if a pvm with a given transport id already exists in the list - this is used to
    /// ensure that step 1 of phase 2 of the AuthMgr protocol is allowed only for already
    /// authenticated instances
    pub fn has_transport_id(&self, transport_id: TransportID) -> bool {
        self.authenticated_pvms.iter().any(|entry| entry.transport_id == transport_id)
    }

    /// Remove a pvm instance via its transport id (upon connection close)
    pub fn remove_via_transport_id(&mut self, transport_id: TransportID) {
        self.authenticated_pvms.retain(|entry| entry.transport_id != transport_id);
    }
}

/// The in-memory data structure representing a new connection requested for a client in step 1 of
/// phase 2 of the AuthMgr protocol. The token is used to authorize this new connection.
/// The same token should be sent over an already authenticated connection setup between AuthMgr FE
/// and AuthMgr BE.
pub struct PendingClientAuthorization {
    /// Token used to authorize a connection
    pub token: Token,
    /// Client connection
    pub client_connection: Box<dyn RawConnection>,
}

impl PendingClientAuthorization {
    /// Constructor for a pending client authorization
    pub fn new(token: Token, client_connection: Box<dyn RawConnection>) -> Self {
        PendingClientAuthorization { token, client_connection }
    }
}

/// The in-memory data structure to keep track of the new connections requested by a particular pVM
/// (identified by the transport id), on behalf of a client. The limit for the number of connections
/// allowed per pVM should be specified when initializing the AuthMgr BE.
pub struct PendingClientAuthorizationsPerPvm {
    /// Transport id of the pvm
    transport_id: TransportID,
    /// List of authentication completed pvms
    capacity: usize,
    /// A list of client connections pending authorization
    pending_clients: Vec<PendingClientAuthorization>,
}

impl PendingClientAuthorizationsPerPvm {
    /// Constructor
    pub fn new(transport_id: TransportID, capacity: usize) -> Result<Self, Error> {
        let mut pending_clients = Vec::<PendingClientAuthorization>::new();
        pending_clients.try_reserve(capacity)?;
        Ok(PendingClientAuthorizationsPerPvm { transport_id, capacity, pending_clients })
    }

    /// Insert a new entry to the list
    pub fn insert(
        &mut self,
        pending_client_authorization: PendingClientAuthorization,
    ) -> Result<(), Error> {
        if self.pending_clients.len() == self.capacity {
            return Err(am_err!(
                MemoryAllocationFailed,
                "Maximum capacity reached for the pending authorizations for the pVM with the
                 transport id: {:?}.",
                self.transport_id
            ));
        }
        if self
            .pending_clients
            .iter()
            .any(|client| client.token == pending_client_authorization.token)
        {
            return Err(am_err!(
                InternalError,
                "a pending client authorzation with the given tokan already exists"
            ));
        }
        self.pending_clients.push(pending_client_authorization);
        Ok(())
    }

    /// Take an entry out of the list, given the token
    pub fn take(&mut self, token: Token) -> Option<PendingClientAuthorization> {
        let index = self
            .pending_clients
            .iter()
            .position(|pending_authorization| pending_authorization.token == token);
        index.map(|index| self.pending_clients.remove(index))
    }
}

/// The in-memory data structure that stores the new connections requested from different pVMs
/// on behalf of the clients, to be authorized and handed over to the trusted services.
/// The limit for the number of entries should be the same as the limit for the authenticated pVMs.
/// We use a separate data structure rather than using `AuthenticatedPvms` or `AuthenticatedPvm`
/// because at the time the requests for initiating a new connection for a client comes in,
/// we do not know whether it is coming from an "authenticated AuthMgr FE component" in the pVM.
pub struct PendingClientAuthorizations {
    /// The allowed number of pvms
    capacity: usize,
    /// The allowed number of pending connections per pvm
    max_entries_per_pvm: usize,
    /// List of pending client connections categorized by pvm
    pending_clients_by_pvm: Vec<PendingClientAuthorizationsPerPvm>,
}

impl PendingClientAuthorizations {
    /// Constructor for PendingClientAuthorizations
    pub fn new(capacity: usize, max_entries_per_pvm: usize) -> Result<Self, Error> {
        let mut pending_clients_by_pvm = Vec::<PendingClientAuthorizationsPerPvm>::new();
        pending_clients_by_pvm.try_reserve(capacity)?;
        Ok(PendingClientAuthorizations { capacity, max_entries_per_pvm, pending_clients_by_pvm })
    }

    /// Insert a pending client authorization
    pub fn insert(
        &mut self,
        transport_id: TransportID,
        pending_client_authorization: PendingClientAuthorization,
    ) -> Result<(), Error> {
        let per_pvm_entry: Option<&mut PendingClientAuthorizationsPerPvm> =
            self.pending_clients_by_pvm.iter_mut().find(|entry| entry.transport_id == transport_id);
        match per_pvm_entry {
            Some(per_pvm_entry) => {
                per_pvm_entry.insert(pending_client_authorization)?;
            }
            None => {
                if self.pending_clients_by_pvm.len() == self.capacity {
                    return Err(am_err!(
                        MemoryAllocationFailed,
                        "Maximum capacity reached for the number of pVMs that can accept
                         pending authorizations."
                    ));
                }
                let mut pending_clients_for_pvm =
                    PendingClientAuthorizationsPerPvm::new(transport_id, self.max_entries_per_pvm)?;
                pending_clients_for_pvm.insert(pending_client_authorization)?;
                self.pending_clients_by_pvm.push(pending_clients_for_pvm);
            }
        }
        Ok(())
    }

    /// Take the pending client authorization that matches the transport id and the token
    pub fn take(
        &mut self,
        transport_id: TransportID,
        token: Token,
    ) -> Option<PendingClientAuthorization> {
        self.pending_clients_by_pvm
            .iter_mut()
            .find(|per_pvm_list| per_pvm_list.transport_id == transport_id)
            .map(|pending_authorizations_per_pvm| pending_authorizations_per_pvm.take(token))?
    }

    /// Remove all the connections identified by the transport id
    pub fn remove_via_transport_id(&mut self, transport_id: TransportID) {
        self.pending_clients_by_pvm
            .retain(|pending_clients_per_pvm| pending_clients_per_pvm.transport_id != transport_id);
    }
}

/// Encapsulation of the full DICE artifacts of a client. This is particularly required for the
/// "policy matching as a service" provided by AuthMgr BE.
pub struct AuthorizedClientFullDiceArtifacts {
    /// Unique sequence number of the client
    pub sequence_number: i32,
    /// Transport id of the pvm that the client belongs to (used to cleanup the cache upon
    /// connection close by the pvm)
    pub transport_id: TransportID,
    /// Client's id (used to cleanup the cache upon client deletion)
    pub client_id: Arc<ClientId>,
    /// Complete DICE artifacts of the client
    pub full_dice_artifacts: DiceArtifacts,
}

/// List of authorized clients with their full DICE artifacts. This is particularly required for the
/// "policy matching as a service" provided by AuthMgr BE.
pub struct AuthorizedClientsGlobalList {
    /// Allowed number of authorized clients
    capacity: usize,
    /// List of authorized clients with their complete set of DICE artifacts (i.e. the leaf DICE
    /// artifacts combined with the pvm DICE artifacts)
    authorized_clients_list: Vec<AuthorizedClientFullDiceArtifacts>,
}

impl AuthorizedClientsGlobalList {
    /// Constructor
    pub fn new(capacity: usize) -> Result<Self, Error> {
        let mut authorized_clients_list = Vec::<AuthorizedClientFullDiceArtifacts>::new();
        authorized_clients_list.try_reserve(capacity)?;
        Ok(AuthorizedClientsGlobalList { capacity, authorized_clients_list })
    }

    /// Retrieve a mutable client given the client's unique sequence number
    pub fn get_mut(&mut self, seq_number: i32) -> Option<&mut AuthorizedClientFullDiceArtifacts> {
        self.authorized_clients_list
            .iter_mut()
            .find(|authorized_client| authorized_client.sequence_number == seq_number)
    }

    /// Insert a new entry to the list
    pub fn insert(
        &mut self,
        authorized_client_full_dice_artifacts: AuthorizedClientFullDiceArtifacts,
    ) -> Result<(), Error> {
        if self.authorized_clients_list.iter().any(|authorized_client| {
            authorized_client.sequence_number
                == authorized_client_full_dice_artifacts.sequence_number
        }) {
            return Err(am_err!(
                InternalError,
                "full  dice artifacts already exists for the unique client sequence number: {:?}.",
                authorized_client_full_dice_artifacts.sequence_number
            ));
        }
        if self.authorized_clients_list.len() == self.capacity {
            return Err(am_err!(
                MemoryAllocationFailed,
                "Capacity for the global list of authorized clients reached."
            ));
        }
        self.authorized_clients_list.push(authorized_client_full_dice_artifacts);
        Ok(())
    }

    /// Remove all entries given a transport id
    pub fn remove_via_transport_id(&mut self, transport_id: TransportID) {
        self.authorized_clients_list
            .retain(|authorized_clients| authorized_clients.transport_id != transport_id);
    }

    /// Remove an entry given the client id
    pub fn remove_via_client_id(&mut self, client_id: &ClientId) {
        self.authorized_clients_list
            .retain(|authorized_clients| *authorized_clients.client_id == *client_id);
    }
}

/// Max sizes of the in-memory data structures to be specified by the implementation of
/// the AuthMgrBE. These numbers may depend on the max number of connections supported by the TEE
/// per process.
pub struct MemoryLimits {
    /// Capacity of the AuthStartedPvms list
    pub capacity_auth_started_pvms: usize,
    /// Capacity of the AuthCompletedPvms list
    pub capacity_auth_completed_pvms: usize,
    /// Number of clients allowed per pvm
    pub max_clients_per_pvm: usize,
}

impl Default for MemoryLimits {
    fn default() -> Self {
        Self {
            capacity_auth_started_pvms: MAX_SIZE_AUTH_STARTED_PVMS,
            capacity_auth_completed_pvms: MAX_SIZE_AUTH_COMPLETED_PVMS,
            max_clients_per_pvm: MAX_AUTHORIZED_CLIENTS_PER_CONNECTION,
        }
    }
}
