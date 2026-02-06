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
    error::{Error, ErrorCode, PolicyMatchingError},
    traits::RawConnection,
    try_to_vec,
};
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use authgraph_core::key::{CertChain, EcVerifyKey};
use authmgr_common::{
    signed_connection_request::{Challenge, TransportID},
    DicePolicy, Token,
};
use coset::CborSerializable;
use log::{error, warn};

/// Version of the data structure format used to store details of a persistent instance
pub const VERSION_PERSISTENT_INSTANCE_CONTEXT: i64 = 1;
/// Version of the data structure format used to store details of a persistent client
pub const VERSION_PERSISTENT_CLIENT_CONTEXT: i64 = 1;

/// Default value for maximum number of entries in the cache for authentication started pVMs
pub const MAX_SIZE_AUTH_STARTED_PVMS: usize = 6;
/// Default value for maximum number of entries in the cache for authenticated pVMs
pub const MAX_SIZE_AUTH_COMPLETED_PVMS: usize = 6;
/// Default value for the maximum number of entries in the cache for authorized clients
/// per connection
pub const MAX_AUTHORIZED_CLIENTS_PER_CONNECTION: usize = 8;

/// Size of an instance identifier in bytes.
/// See the documentation of instance id in AuthMgr README at:
/// hardware/interfaces/security/see/authmgr/aidl/README.md
pub const INSTANCE_IDENTIFIER_SIZE: usize = 64;

/// Size of an UUID in bytes
pub const UUID_SIZE: usize = 16;

/// Test VM primary UUID is 07590497-b72d-4434-ab36-51442e130536, as per AuthMgr README at:
/// hardware/interfaces/security/see/authmgr/aidl/README.md
pub const TEST_VM_PRIMARY_UUID: [u8; UUID_SIZE] = [
    0x07, 0x59, 0x04, 0x97, 0xb7, 0x2d, 0x44, 0x34, 0xab, 0x36, 0x51, 0x44, 0x2e, 0x13, 0x05, 0x36,
];

// A persistent system vm has the first byte of its instance id as: 0x80 0x00 0x00 0x00
// A persistent vendor vm has the first byte of its instance id as: 0xff 0xff 0xff 0xff
// To test for a persistent instance, we check whether the most significant bit (MSB) of byte 0 is 1
const MSB_MASK: u8 = 0b1000_0000;

// Test VM primary UUID is 16 bytes long, starting from the 16th byte of instance-id
const TEST_VM_PRIMARY_UUID_BEGIN_OFFSET: usize = 16;
const TEST_VM_PRIMARY_UUID_END_OFFSET_EXCLUSIVE: usize =
    TEST_VM_PRIMARY_UUID_BEGIN_OFFSET + UUID_SIZE;

// Test VM secondary UUID is 16 bytes long, starting from the 32nd byte of instance-id
const TEST_VM_SECONDARY_UUID_BEGIN_OFFSET: usize = 32;
const TEST_VM_SECONDARY_UUID_END_OFFSET_EXCLUSIVE: usize =
    TEST_VM_SECONDARY_UUID_BEGIN_OFFSET + UUID_SIZE;

/// Type alias for an instance-id passed into step 1 of phase 1
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct InstanceIdentifier(pub [u8; INSTANCE_IDENTIFIER_SIZE]);

impl InstanceIdentifier {
    /// Try to construct an instance-id from the  given byte slice
    pub fn try_new(instance_id_data: &[u8]) -> Result<Self, Error> {
        let instance_id_size = instance_id_data.len();
        let instance_id: [u8; INSTANCE_IDENTIFIER_SIZE] =
            instance_id_data.try_into().map_err(|_e| {
                am_err!(
                    InvalidInstanceIdentifier,
                    "instance-id expected size: {:?}, actual size: {:?}",
                    INSTANCE_IDENTIFIER_SIZE,
                    instance_id_size
                )
            })?;
        Ok(Self(instance_id))
    }

    /// Create an instance id for a test vm, given the secondary UUID that uniquely identifies the
    /// test vm. This method is useful for VTS tests.
    pub fn new_for_test_vm(secondary_uuid: [u8; UUID_SIZE]) -> Self {
        let mut test_vm_instance_id = [0u8; INSTANCE_IDENTIFIER_SIZE];
        // first byte of a system persistent vm is same as the MSB_MASK
        test_vm_instance_id[0] = MSB_MASK;
        test_vm_instance_id
            [TEST_VM_PRIMARY_UUID_BEGIN_OFFSET..TEST_VM_PRIMARY_UUID_END_OFFSET_EXCLUSIVE]
            .copy_from_slice(TEST_VM_PRIMARY_UUID.as_slice());
        test_vm_instance_id
            [TEST_VM_SECONDARY_UUID_BEGIN_OFFSET..TEST_VM_SECONDARY_UUID_END_OFFSET_EXCLUSIVE]
            .copy_from_slice(secondary_uuid.as_slice());
        Self(test_vm_instance_id)
    }

    /// A helper function to distinguish persistent instances from non-persistent instances, via the
    /// instance identifier.
    /// Secure storage invariant: we cannot allow a non-persistent pVM connect to secure storage
    /// without the secure storage knowing that it is a non-persistent client. Therefore, the
    /// AuthMgr BE should know whether a given pVM is persistent or not.
    /// See the instance-id schema defined in AuthMgr README at:
    /// hardware/interfaces/security/see/authmgr/aidl/README.md
    pub fn is_persistent(&self) -> bool {
        // Most significant bit of byte 0 is set to 1 in persistent VMs' instance ids.
        self.0[0] & MSB_MASK != 0
    }

    /// A helper function to identify whether a VM instance is a test VM, given its instance-id.
    /// See instance-id schema at hardware/interfaces/security/see/authmgr/aidl/README.md
    pub fn is_test(&self) -> bool {
        self.0[TEST_VM_PRIMARY_UUID_BEGIN_OFFSET..TEST_VM_PRIMARY_UUID_END_OFFSET_EXCLUSIVE]
            == TEST_VM_PRIMARY_UUID
    }

    /// Get the instance id data as a vector of bytes
    pub fn try_to_vec(&self) -> Result<Vec<u8>, PolicyMatchingError> {
        Ok(try_to_vec(&self.0)?)
    }
}

/// Type alias for a client identifier of 64 bytes. This identifier is assigned by the pVM.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ClientId(pub Vec<u8>);

/// Encapsulates the instance metadata
pub struct InstanceMetaData {
    /// A reference to an arc pointing to the instance identifier
    pub instance_id: Arc<InstanceIdentifier>,
    /// Instance sequence number
    pub instance_seq_number: i64,
    /// DICE chain mode for the instance
    pub dice_chain_mode: DiceChainModeForPvm,
    /// Storage mode for the instance
    pub storage_mode: StorageModeForPvm,
}

/// Information stored in an authenticated connection established between a pVM and the AuthMgr BE.
/// This information is re-used when serving multiple requests for authorizing the
/// clients in the pVM
pub struct AuthenticatedConnectionInfo {
    /// Instance id of the pvm
    pub instance_id: Arc<InstanceIdentifier>,
    /// Transport id of the pvm
    pub transport_id: TransportID,
    /// Unique sequence number assigned to the instance by the AuthMgr BE
    pub instance_seq_number: i64,
    /// DICE chain mode for the pvm derived from the DICE certificate chain
    pub dice_chain_mode: DiceChainModeForPvm,
    /// Storage mode derived based on which storage file path allocated to the given instance-id is
    /// used to read the instance-context
    pub storage_mode: StorageModeForPvm,
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

impl AuthenticatedConnectionInfo {
    /// Populate the information to be stored in-memory in the connection state
    pub fn new(
        instance_metadata: InstanceMetaData,
        transport_id: TransportID,
        dice_artifacts: DiceArtifacts,
        pub_signing_key: EcVerifyKey,
        is_persistent: bool,
        max_num_of_clients: usize,
    ) -> Result<Self, Error> {
        let mut authorized_clients = Vec::<AuthorizedClient>::new();
        authorized_clients.try_reserve(max_num_of_clients)?;
        Ok(Self {
            instance_id: instance_metadata.instance_id,
            transport_id,
            instance_seq_number: instance_metadata.instance_seq_number,
            dice_chain_mode: instance_metadata.dice_chain_mode,
            storage_mode: instance_metadata.storage_mode,
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

    /// Remove authorized client via the sequence number
    pub fn remove_via_sequence_number(&mut self, sequence_number: i64) {
        self.authorized_clients.retain(|client| client.sequence_number != sequence_number);
    }
}

/// Encapsulation of the DICE certificate chain and the DICE policy used to validate it
#[derive(Clone)]
pub struct DiceArtifacts {
    /// DICE certificate chain
    pub cert_chain: Arc<CertChain>,
    /// DICE poicy
    pub policy: Arc<DicePolicy>,
}

/// Enum representing the three different outcomes of matching a given DICE policy against the
/// client's latest DICE chain and comparing the given DICE policy with the client's latest DICE
/// policy.
pub enum PolicyMatchingResult {
    /// The given policy matches the DICE chain and the policy is the latest one
    Success,

    /// The given policy matches the DICE chain but it is not the latest policy
    MatchedNotCurrent,

    /// The given policy does not match the DICE chain
    Failed,
}

/// Information associated with an authorized client. This information is used to check for
/// duplicate authorization attempts for the same client.
#[derive(Clone)]
pub struct AuthorizedClient {
    /// Client id
    pub client_id: Arc<ClientId>,
    /// Unique sequence number assigned to the client by the AuthMgr BE
    pub sequence_number: i64,
    /// DICE policy of the client
    pub policy: Arc<DicePolicy>,
}

impl AuthorizedClient {
    /// Update the client's policy with the given policy
    pub fn update_policy(&mut self, updated_policy: &Arc<DicePolicy>) {
        self.policy = Arc::clone(updated_policy);
    }
}

/// Type alias to identify a persistent context created for an instance.
pub type PersistentInstanceContext = PersistentContext;
/// Type alias to identify a persistent context created for a client.
pub type PersistentClientContext = PersistentContext;

/// Information of a persistent pvm instance or client stored in the persistent secure storage.
#[derive(Debug, Clone, PartialEq)]
pub struct PersistentContext {
    /// Version of the data structure format
    pub version: i64,
    /// Unique sequence number assigned by the AuthMgrBE
    pub sequence_number: i64,
    /// DICE policy
    pub dice_policy: Arc<DicePolicy>,
}

impl PersistentContext {
    const SEQUENCE_NUM_OFFSET: usize = 8;
    const SEQUENCE_NUM_SIZE: usize = 8;
    const MIN_SIZE: usize = Self::SEQUENCE_NUM_OFFSET + Self::SEQUENCE_NUM_SIZE;
    const _MIN_SIZE_ASSERT: () = assert!(Self::MIN_SIZE == 16);
    /// Define the error message returned during deserialization for insufficient data
    pub const ERROR_MSG_INSUFFICIENT_DATA: &str = "insufficient data for PersistentContext";

    /// Serialize `PersistentContext` into a byte vector
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut v = Vec::new();
        let encoded_policy = (*self.dice_policy).clone().to_vec().map_err(|e| {
            error!("failed to encode DicePolicy: {:?}", e);
            am_err!(InternalError, "failed to encode DicePolicy")
        })?;
        v.try_reserve(Self::MIN_SIZE + encoded_policy.len())?;
        v.extend_from_slice(&self.version.to_ne_bytes());
        v.extend_from_slice(&self.sequence_number.to_ne_bytes());
        v.extend_from_slice(&encoded_policy);
        Ok(v)
    }

    /// Deserialize `PersistentContext` from a bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        // Minimum size in bytes (version and sequence number)
        if data.len() <= Self::MIN_SIZE {
            return Err(am_err!(InternalError, "{}", Self::ERROR_MSG_INSUFFICIENT_DATA));
        }
        let version = i64::from_ne_bytes(data[0..Self::SEQUENCE_NUM_OFFSET].try_into()?);
        let sequence_number =
            i64::from_ne_bytes(data[Self::SEQUENCE_NUM_OFFSET..Self::MIN_SIZE].try_into()?);
        let dice_policy_bytes = &data[Self::MIN_SIZE..];
        let dice_policy = Arc::new(DicePolicy::from_slice(dice_policy_bytes).map_err(|e| {
            error!("failed to decode DicePolicy: {:?}", e);
            am_err!(InternalError, "failed to decode DicePolicy")
        })?);
        Ok(PersistentInstanceContext { version, sequence_number, dice_policy })
    }
}

/// Enum with two variants indicating whether or not all the certificates of the DICE chain of a pVM
/// have mode=Normal or at least one has a mode value that is different from Nomal.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiceChainModeForPvm {
    /// At least one certificate of the DICE chain has a mode value that is different from Normal
    NotNormal = 0,
    /// All the certificates of the DICE chain have mode=Normal
    Normal = 1,
}

/// Enum with two variants indicating whether the instance-context of a pVM is stored in the area
/// (i.e. storage file path) allocated for the given instance-id with dice-chain-mode = Normal or
/// dice-chain-mode = NotNormal.
/// We need a separate enum that is different from `DiceChainModeForPvm` enum to represent this
/// because a pVM with dice-chain-mode = NotNormal may read from the instance-context stored in
/// the area allocated for the same instance-id with dice-chain-mode = Normal, if the dice policy
/// allows it (i.e. DICE policy does not contain constraints on dice chain mode).
/// However, an instance with dice-chain-mode = NotNormal, is not allowed to write to such
/// instance-context stored in the area allocated for the instance-id with dice-chain-mode = Normal.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageModeForPvm {
    /// Instance-context of a pVM is stored in the area allocated for the instance-id with
    /// dice-chain-mode = NotNormal.
    NotNormal = 0,
    /// Instance-context of a pVM is stored in the area allocated for the instance-id with
    /// dice-chain-mode = Normal.
    Normal = 1,
}

impl TryFrom<u8> for StorageModeForPvm {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(StorageModeForPvm::NotNormal),
            1 => Ok(StorageModeForPvm::Normal),
            _ => Err(am_err!(InternalError, "invalid value for StorageModeForPvm")),
        }
    }
}

/// Encapsulates information about a pVM instance which has completed step 1 of phase 1 of the
/// AuthMgr protocol  (i.e. `init_authentication`), but not step 2 (i.e. `complete_authentication`).
#[derive(Clone, PartialEq)]
pub struct AuthStartedPvm {
    /// Transport id of the pvm (a.k.a. VM ID)
    pub transport_id: TransportID,
    /// Instance id of the pvm
    pub instance_id: Arc<InstanceIdentifier>,
    /// Dice chain mode
    pub dice_chain_mode: DiceChainModeForPvm,
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
        sequence_number: i64,
    ) -> Result<(), Error> {
        // Remove any other entries in `AuthStartedPvms` based on the authenticated instance id and
        // the DICE chain mode to enforce the Trust On First Use (TOFU) principle and prioritizing
        // instances with dice chain mode=Normal.
        auth_started_pvms
            .remove_via_instance_id_and_dice_chain_mode(&self.instance_id, self.dice_chain_mode);
        authenticated_pvms.insert(self, sequence_number)
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

    /// Remove all entries given an instance id and dice chain mode - this is used to remove all
    /// entries with a given tuple of (instance id, dice chain mode) of an authenticated pVM.
    /// Furthermore, if the dice chain mode = Normal, this removes any entry with the given
    /// instance id and dice chain mode = NotNormal.
    pub fn remove_via_instance_id_and_dice_chain_mode(
        &mut self,
        instance_id: &InstanceIdentifier,
        dice_chain_mode: DiceChainModeForPvm,
    ) {
        self.auth_started_pvms.retain(|entry| {
            if &*entry.instance_id != instance_id {
                // This is not our instance id, keep it
                return true;
            }

            if dice_chain_mode == DiceChainModeForPvm::Normal {
                // If we're getting rid of a VM with mode Normal, it's NotNormal
                // counterpart also needs to go.
                false
            } else {
                // Get rid of the VM only if its mode matches the one we're looking for.
                dice_chain_mode != entry.dice_chain_mode
            }
        });
    }
}

/// Encapsulates information about a pVM instance which has completed phase 1 of the AuthMgr
/// protocol
#[derive(PartialEq)]
pub struct AuthenticatedPvm {
    /// Instance id of the pvm
    pub instance_id: Arc<InstanceIdentifier>,
    /// Dice chain mode
    pub dice_chain_mode: DiceChainModeForPvm,
    /// Instance sequence number
    pub sequence_number: i64,
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
    pub fn insert(
        &mut self,
        auth_started_pvm: &AuthStartedPvm,
        sequence_number: i64,
    ) -> Result<(), Error> {
        if self.authenticated_pvms.len() == self.capacity {
            return Err(am_err!(
                MemoryAllocationFailed,
                "Maximum number of authenticated pvms reached."
            ));
        }
        let authenticated_pvm = AuthenticatedPvm {
            instance_id: Arc::clone(&auth_started_pvm.instance_id),
            dice_chain_mode: auth_started_pvm.dice_chain_mode,
            sequence_number,
            transport_id: auth_started_pvm.transport_id,
        };
        self.authenticated_pvms.push(authenticated_pvm);
        Ok(())
    }

    /// Check if a pvm with a given (instance id, dice chain mode) tuple already exists in the list.
    /// This is used to prevent initAuthentication attempts for already authenticated instances.
    pub fn has_instance_id_and_dice_chain_mode(
        &self,
        instance_id: &InstanceIdentifier,
        dice_chain_mode: DiceChainModeForPvm,
    ) -> bool {
        self.authenticated_pvms.iter().any(|entry| {
            &*entry.instance_id == instance_id && entry.dice_chain_mode == dice_chain_mode
        })
    }

    /// Check if a pvm with a given transport id already exists in the list - this is used to
    /// ensure that step 1 of phase 2 of the AuthMgr protocol is allowed only for already
    /// authenticated instances
    pub fn has_transport_id(&self, transport_id: TransportID) -> bool {
        self.authenticated_pvms.iter().any(|entry| entry.transport_id == transport_id)
    }

    /// Check if a pvm with a given sequence number already exists in the list - this is used to
    /// perform duplication checks in completeAuthentication step (i.e. step 2 of phase 1) for
    /// already authenticated pvms
    pub fn has_sequence_number(&self, sequence_number: i64) -> bool {
        self.authenticated_pvms.iter().any(|entry| entry.sequence_number == sequence_number)
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
    pub sequence_number: i64,
    /// Transport id of the pvm that the client belongs to (used to cleanup the cache upon
    /// connection close by the pvm)
    pub transport_id: TransportID,
    /// Client's id (used to cleanup the cache upon client deletion)
    pub client_id: Arc<ClientId>,
    /// Complete DICE artifacts of the client
    pub full_dice_artifacts: DiceArtifacts,
    /// Identifier of the pVM instance that the client is running in
    pub instance_id: Arc<InstanceIdentifier>,
    /// Persistent status
    pub is_persistent: bool,
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
    pub fn get_mut(&mut self, seq_number: i64) -> Option<&mut AuthorizedClientFullDiceArtifacts> {
        self.authorized_clients_list
            .iter_mut()
            .find(|authorized_client| authorized_client.sequence_number == seq_number)
    }

    /// Retrieve an immutable client given the client's unique sequence number
    pub fn get(&self, seq_number: i64) -> Option<&AuthorizedClientFullDiceArtifacts> {
        self.authorized_clients_list
            .iter()
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

    /// Remove an entry given the client sequence number
    pub fn remove_via_sequence_number(&mut self, sequence_number: i64) {
        self.authorized_clients_list
            .retain(|authorized_client| authorized_client.sequence_number != sequence_number);
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

/// Enum representing the different stages of authentication life cycle for a `RpcConnection`
pub enum ConnectionAuthState {
    /// None of the steps of authentication has been completed
    None,
    /// Step 1 of phase 1 (i.e. `initAuthentication` has been completed successfully)
    AuthenticationStarted,
    /// Phase 1 has been completed successfully
    AuthenticationCompleted(Box<AuthenticatedConnectionInfo>),
}

/// At the time of enforcng rollback protection on a client, the client's information can be
/// read from the cache or from the storage. This enum wraps the two types of information
/// that we have about the client in the two cases.
pub enum ClientInfoAtRollbackProtection<'a> {
    /// If the client information is read from the cache, what we have is the client's policy
    FromCache(&'a mut AuthorizedClient),
    /// If the client information is read from the storage, we have the struct holding the
    /// client context
    FromPersistentStorage(&'a mut PersistentClientContext),
}
impl<'a> ClientInfoAtRollbackProtection<'a> {
    /// Check if the client info has the same policy as the given policy
    pub fn has_same_policy(&'a self, given_policy: &DicePolicy) -> bool {
        match self {
            Self::FromCache(authorized_client) => *authorized_client.policy == *given_policy,
            Self::FromPersistentStorage(ctx) => *ctx.dice_policy == *given_policy,
        }
    }

    /// Retrieve the DICE policy as a `DicePolicy` object
    pub fn get_policy(&'a self) -> Result<&'a DicePolicy, Error> {
        match self {
            Self::FromCache(authorized_client) => Ok(&authorized_client.policy),
            Self::FromPersistentStorage(ctx) => Ok(&ctx.dice_policy),
        }
    }
}

/// Encapsulates the client metadata required by trusted HAL services
pub struct ClientMetaData {
    /// Identifier of the pVM instance
    pub instance_id: InstanceIdentifier,
    /// Identifier assigned to the client by the pVM
    pub client_id: ClientId,
    /// Is the instance/client persistent
    pub is_persistent: bool,
}

/// Encapsulates the metadata included in a file name of a context file
pub struct ContextFileNameMetaData<'a> {
    /// Prefix indicating the context file type (e.g. instance or client context)
    pub context_prefix: &'a str,
    /// Instance identifier
    pub instance_id: InstanceIdentifier,
    /// Storage mode
    pub storage_mode: StorageModeForPvm,
}

/// Encodes data into the provided buffer. Returns a &str pointing into that buffer.
pub fn hex_encode_into<'a>(data: &[u8], buffer: &'a mut [u8]) -> Result<&'a str, Error> {
    // hex needs 2 bytes per input byte
    if buffer.len() != data.len() * 2 {
        return Err(am_err!(
            InternalError,
            "Buffer has incorrect size, expected: {:?}, got: {:?}",
            data.len() * 2,
            buffer.len()
        ));
    }

    hex::encode_to_slice(data, buffer)
        .map_err(|e| am_err!(InternalError, "Hex encode failed: {:?}", e))?;

    // Convert the used portion of the buffer to a &str
    core::str::from_utf8(&buffer[..data.len() * 2])
        .map_err(|e| am_err!(InternalError, "UTF-8 conversion failed: {:?}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{Storage, WriteMode};
    use alloc::string::String;
    use alloc::sync::Arc;
    use alloc::vec;
    use authgraph_core_test::{
        create_dice_cert_chain_for_guest_os, SAMPLE_INSTANCE_HASH, TEST_OS_COMPONENT_NAME,
    };
    use authmgr_common_util::get_constraints_spec_for_trusty_vm;

    #[test]
    fn test_persistent_context_serialization_roundtrip() {
        // Create DICE chain for a pvm instance
        let (_sign_key, _cdi_values, cert_chain_bytes) = create_dice_cert_chain_for_guest_os(
            Some(SAMPLE_INSTANCE_HASH),
            1,
            true, /*normal mode*/
        );
        // Create constraints spec
        let constraint_spec = get_constraints_spec_for_trusty_vm(TEST_OS_COMPONENT_NAME);
        // Create policy given constraints spec and DICE chain
        let policy = dice_policy_builder::policy_for_dice_chain(&cert_chain_bytes, constraint_spec)
            .expect("failed to building policy 1");
        let dice_policy = Arc::new(policy);
        let context = PersistentContext {
            version: 1,
            sequence_number: 12345,
            dice_policy: Arc::clone(&dice_policy),
        };

        let bytes = context.to_bytes().unwrap();
        let new_context = PersistentContext::from_bytes(&bytes).unwrap();

        assert_eq!(context, new_context);
    }

    #[test]
    fn test_persistent_context_from_bytes_less_than_min_size_error() {
        let bytes = vec![0; 15];
        let result = PersistentContext::from_bytes(&bytes);
        assert!(result.is_err());
        assert_eq!(ErrorCode::InternalError, result.as_ref().unwrap_err().0);
        assert!(result.unwrap_err().1.contains(PersistentContext::ERROR_MSG_INSUFFICIENT_DATA));
    }

    #[test]
    fn test_persistent_context_from_bytes_min_size_error() {
        let bytes = vec![0; 16];
        let result = PersistentContext::from_bytes(&bytes);
        assert!(result.is_err());
        assert_eq!(ErrorCode::InternalError, result.as_ref().unwrap_err().0);
        assert!(result.unwrap_err().1.contains(PersistentContext::ERROR_MSG_INSUFFICIENT_DATA));
    }

    // Security VM Instance ID parameters
    // "vm_partition": "system",
    // "is_vm_persistent": true,
    // "vm_primary_uuid": "6c07e3dc-79e1-45a3-936d-b5d73a978f41"
    const SECURITY_VM_INSTANCE_ID: InstanceIdentifier = InstanceIdentifier([
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x6c, 0x07, 0xe3, 0xdc, 0x79, 0xe1, 0x45, 0xa3, 0x93, 0x6d, 0xb5, 0xd7, 0x3a, 0x97,
        0x8f, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ]);

    // A random persistent vendor VM
    const PERSISTENT_VENDOR_VM_INSTANCE_ID: InstanceIdentifier = InstanceIdentifier([
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x3c, 0x07, 0xe3, 0xdc, 0x79, 0xe1, 0x45, 0xa3, 0x93, 0x6d, 0xb5, 0xd7, 0x3a, 0x97,
        0x8f, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ]);

    //  A random non-persistent system VM
    const NON_PERSISTENT_VM_INSTANCE_ID: InstanceIdentifier = InstanceIdentifier([
        0x77, 0x77, 0x77, 0x77, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x5c, 0x07, 0xe3, 0xdc, 0x79, 0xe1, 0x45, 0xa3, 0x93, 0x6d, 0xb5, 0xd7, 0x3a, 0x97,
        0x8f, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ]);

    // Persistent test vm
    // Parameters from packages/modules/Virtualization/guest/trusty/test_vm/
    // test_vm_instance_id_config.json:
    // "vm_partition": "system",
    // "is_vm_persistent": true,
    // "vm_primary_uuid": "07590497-b72d-4434-ab36-51442e130536",
    // "vm_secondary_uuid": "0bea1ffc-b036-4d3a-8268-a5a041ade6b8"
    const TEST_VM_INSTANCE_ID: InstanceIdentifier = InstanceIdentifier([
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x07, 0x59, 0x04, 0x97, 0xb7, 0x2d, 0x44, 0x34, 0xab, 0x36, 0x51, 0x44, 0x2e, 0x13,
        0x05, 0x36, 0x0b, 0xea, 0x1f, 0xfc, 0xb0, 0x36, 0x4d, 0x3a, 0x82, 0x68, 0xa5, 0xa0, 0x41,
        0xad, 0xe6, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ]);

    #[test]
    fn test_for_persistent_instance_id() {
        assert!(SECURITY_VM_INSTANCE_ID.is_persistent());
        assert!(PERSISTENT_VENDOR_VM_INSTANCE_ID.is_persistent());
        assert!(!NON_PERSISTENT_VM_INSTANCE_ID.is_persistent());
    }

    #[test]
    fn test_for_test_instance_id() {
        assert!(TEST_VM_INSTANCE_ID.is_test());
        assert!(!SECURITY_VM_INSTANCE_ID.is_test());
    }

    #[test]
    fn test_instance_id_for_test_vm() {
        // UUID = df261d53-3789-424b-8feb-7b80abae009c
        let secondary_uuid: [u8; 16] = [
            0xdf, 0x26, 0x1d, 0x53, 0x37, 0x89, 0x42, 0x4b, 0x8f, 0xeb, 0x7b, 0x80, 0xab, 0xae,
            0x00, 0x9c,
        ];
        let instance_id = InstanceIdentifier::new_for_test_vm(secondary_uuid);
        assert!(instance_id.is_test());
        assert!(instance_id.is_persistent());
    }

    #[test]
    fn test_context_file_name_with_instance_id_roundtrip() {
        struct MockDevice;
        impl Storage for MockDevice {
            fn read(&self, _file_path: &str) -> Result<Option<Vec<u8>>, Error> {
                unimplemented!()
            }
            fn write(
                &mut self,
                _file_path: &str,
                _data: &[u8],
                _write_mode: WriteMode,
            ) -> Result<(), Error> {
                unimplemented!()
            }
            fn list_file_names(&self) -> Result<Vec<String>, Error> {
                unimplemented!()
            }
            fn delete_file(&mut self, _file_path: &str) -> Result<(), Error> {
                unimplemented!()
            }
        }
        let dev = MockDevice;
        let test_vm_context_file_name = dev
            .build_storage_file_path_for_instance(&TEST_VM_INSTANCE_ID, &StorageModeForPvm::Normal)
            .expect("error in building instance context file name");
        let extracted_test_vm_instance_id = dev
            .extract_metadata_from_context_file_name(&test_vm_context_file_name)
            .expect("error in extracting instance id from test vm context file name")
            .instance_id;
        assert_eq!(extracted_test_vm_instance_id, TEST_VM_INSTANCE_ID);

        let client_id = vec![
            0xc0, 0xb6, 0x8b, 0x1d, 0x2d, 0xce, 0x42, 0xea, 0x83, 0x98, 0xcc, 0xc4, 0xb6, 0x14,
            0xb4, 0x3c,
        ];
        let test_vm_client_context_file_name = dev
            .build_storage_file_path_for_client(
                &TEST_VM_INSTANCE_ID,
                &StorageModeForPvm::Normal,
                12,
                &ClientId(client_id),
            )
            .expect("error in building client context file name");
        let extracted_instance_id = dev
            .extract_metadata_from_context_file_name(&test_vm_client_context_file_name)
            .expect("error in extracting instance id from test vm client context file name")
            .instance_id;
        assert_eq!(extracted_instance_id, TEST_VM_INSTANCE_ID);
    }
}
