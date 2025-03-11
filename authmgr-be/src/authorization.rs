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

//! Reference implementation of the `IAuthMgrAuthorization.aidl` for the AuthMgr Backend.
// TODO: remove this
#![allow(dead_code)]
use crate::{
    am_err,
    data_structures::{
        AuthStartedPvm, AuthStartedPvms, AuthenticatedConnectionState, AuthenticatedPvms,
        AuthorizedClientsGlobalList, DiceArtifacts, MemoryLimits, PendingClientAuthorizations,
        PersistentInstanceContext, VERSION_PERSISTENT_INSTANCE_CONTEXT,
    },
    error::{Error, ErrorCode},
    traits::{CryptoTraitImpl, Device, PersistentStorage, RpcConnection},
};
use alloc::boxed::Box;
use alloc::sync::Arc;
use authgraph_core::key::{CertChain, InstanceIdentifier, Policy};
use authmgr_common::{
    match_dice_chain_with_policy,
    signed_connection_request::{Challenge, ConnectionRequest},
};
use coset::CborSerializable;

/// Data structure encapsulating AuthMgr backend.
/// Note that we assume the use of AuthMgrBE in single threaded environments. It is planned for the
/// future to make AuthMgrBE usable in multi-threaded environments b/369207531 and to make all
/// allocations fallible b/401550040.
pub struct AuthMgrBE {
    crypto: CryptoTraitImpl,
    device: Box<dyn Device>,
    persistent_storage: Box<dyn PersistentStorage>,
    auth_started_pvms: AuthStartedPvms,
    auth_completed_pvms: AuthenticatedPvms,
    latest_global_sequence_number: LatestGlobalSeqNum,
    pending_client_authorizations: PendingClientAuthorizations,
    authorized_clients: AuthorizedClientsGlobalList,
    memory_limits: MemoryLimits,
}

/// Data structure encapsulating the global sequence number - which is used to assign a unique
/// identifier to the instances and clients by the AuthMgr BE
pub struct LatestGlobalSeqNum(i32);

impl LatestGlobalSeqNum {
    /// Constructs an instance of the in-memory global sequence number given the latest global
    /// sequence number which is read from the persistent storage
    pub fn new(latest_global_seq_num: i32) -> Self {
        Self(latest_global_seq_num)
    }

    /// Return the current global sequence number and increment the global sequence number in the
    /// persistent storage and in this in-memory instance
    pub fn fetch_and_increment(
        &mut self,
        persistent_storage: &mut dyn PersistentStorage,
    ) -> Result<i32, Error> {
        let current_global_seq_num = self.0;
        self.0 = persistent_storage.increment_global_sequence_number()?;
        Ok(current_global_seq_num)
    }
}

impl AuthMgrBE {
    /// Initialize AuthMgr BE
    pub fn new(
        crypto: CryptoTraitImpl,
        device: Box<dyn Device>,
        mut persistent_storage: Box<dyn PersistentStorage>,
        memory_limits: MemoryLimits,
    ) -> Result<Self, Error> {
        let auth_started_pvms = AuthStartedPvms::new(memory_limits.capacity_auth_started_pvms)?;
        let auth_completed_pvms =
            AuthenticatedPvms::new(memory_limits.capacity_auth_completed_pvms)?;
        let pending_client_authorizations = PendingClientAuthorizations::new(
            memory_limits.capacity_auth_completed_pvms,
            memory_limits.max_clients_per_pvm,
        )?;
        let authorized_clients = AuthorizedClientsGlobalList::new(
            memory_limits.capacity_auth_completed_pvms * memory_limits.max_clients_per_pvm,
        )?;
        // If this is the first time the AuthMgr BE is running after the first boot of the device,
        // initialize the global sequence number, otherwise, read it from the AuthMgr BE's storage
        let latest_global_sequence_number =
            LatestGlobalSeqNum(persistent_storage.get_or_create_global_sequence_number()?);
        Ok(AuthMgrBE {
            crypto,
            device,
            persistent_storage,
            auth_started_pvms,
            auth_completed_pvms,
            latest_global_sequence_number,
            pending_client_authorizations,
            authorized_clients,
            memory_limits,
        })
    }

    /// Step 1 of phase 1
    pub fn init_authentication(
        &mut self,
        connection: &dyn RpcConnection,
        cert_chain: &[u8],
        ext_instance_id: Option<&[u8]>,
    ) -> Result<Challenge, Error> {
        // Check if the connection is already authenticated by retrieving the connection state
        if connection.get_authenticated_state()?.is_some() {
            return Err(am_err!(
                InstanceAlreadyAuthenticated,
                "connection is already authenticated"
            ));
        }

        // Retrieve the transport ID
        let transport_id = connection.get_peer_transport_id()?;

        // Decode the DICE certificate chain
        let cert_chain = CertChain::from_slice(cert_chain)?;

        // First, extract the instance identifier from the DICE chain. Only if it is not present,
        // check if a valid instance identifier is provided via the optional parameter
        let instance_id: InstanceIdentifier =
            match cert_chain.extract_instance_identifier_in_guest_os_entry()? {
                Some(id) => id,
                None => ext_instance_id.map(|id| id.to_vec()).ok_or(am_err!(
                    InvalidInstanceIdentifier,
                    "Instance identifier is neither present in the DICE cert chain,
                        nor in the optional argument"
                ))?,
            };

        // Check for duplicated authentication attempts.
        // We check with the instance id and transport id separately, and not with the combination
        // of the two, because the latter allows the same pVM to be spawned twice (resulting in two
        // different transport ids and the same instance id) and connected, which we want to avoid.
        if self.auth_completed_pvms.has_instance_id(&instance_id) {
            return Err(am_err!(
                InstanceAlreadyAuthenticated,
                "duplicated authentication attempt with the instance id: {:?}!",
                instance_id
            ));
        }
        if self.auth_completed_pvms.has_transport_id(transport_id) {
            return Err(am_err!(
                InstanceAlreadyAuthenticated,
                "duplicated authentication attempt with the transport id: {:?}!",
                transport_id
            ));
        }
        // We filter duplicated entries in `AuthStartedPvms` via the transport id only.
        // We do not filter via instance id here in order to prevent a potental DoS attack where an
        // impersonating pVM starts authentication with a genuine pVM's instance id, but never
        // completes.
        if self.auth_started_pvms.has_transport_id(transport_id) {
            return Err(am_err!(
                AuthenticationAlreadyStarted,
                "duplicated attempt to start authentication!"
            ));
        }
        let mut challenge = [0; 32];
        self.crypto.rng.fill_bytes(&mut challenge);
        // TODO: b/401550040. Use fallible allocation when Rust supports it.
        self.auth_started_pvms.insert(AuthStartedPvm {
            transport_id,
            instance_id: Arc::new(instance_id),
            challenge,
            cert_chain: Arc::new(cert_chain),
        });
        Ok(challenge)
    }

    /// Step 2 of phase 1
    pub fn complete_authentication(
        &mut self,
        connection: &mut dyn RpcConnection,
        signed_response: &[u8],
        dice_policy: &[u8],
    ) -> Result<(), Error> {
        // Check if the connection is already authenticated by retrieving the connection state
        if connection.get_authenticated_state()?.is_some() {
            return Err(am_err!(
                InstanceAlreadyAuthenticated,
                "connection is already authenticated"
            ));
        }

        // Retrieve the transport ID
        let peer_transport_id = connection.get_peer_transport_id()?;
        let auth_started_entry =
            self.auth_started_pvms.take_via_transport_id(peer_transport_id).ok_or(am_err!(
                AuthenticationNotStarted,
                "An authentication started pVM was not found for the given transport id"
            ))?;
        // Check for duplicated authentication attempts to enforce Trust On First Use (TOFU).
        if self.auth_completed_pvms.has_instance_id(&auth_started_entry.instance_id) {
            return Err(am_err!(
                InstanceAlreadyAuthenticated,
                "duplicated authentication attempt!"
            ));
        }
        // Validate the DICE cert chain and retrieve the signature verification key
        let sig_verification_key =
            (*auth_started_entry.cert_chain).validate(&*self.crypto.ecdsa).map_err(|_e| {
                am_err!(InvalidDiceCertChain, "failed to validate the DICE cert chain.")
            })?;

        // Authenticate the client by validating their signature on the response to the challenge.
        // Construct the expected `ConnectionRequest` CBOR structure as the payload of the signature
        let expected_conn_req = ConnectionRequest::new_for_ffa_transport(
            auth_started_entry.challenge,
            peer_transport_id,
            self.device.get_self_transport_id()?,
        );
        expected_conn_req
            .verify(signed_response, &sig_verification_key, &*self.crypto.ecdsa)
            .map_err(|_e| {
                am_err!(
                    SignatureVerificationFailed,
                    "failed to verify signature on the connection request"
                )
            })?;

        let given_dice_policy = Policy(dice_policy.to_vec());
        let is_persistent = self.device.is_persistent_instance(&auth_started_entry.instance_id)?;
        let instance_seq_number = if is_persistent {
            self.handle_rollback_protection_for_persistent_instance(
                &auth_started_entry.instance_id,
                &given_dice_policy,
                &auth_started_entry.cert_chain,
            )?
        } else {
            // TODO: b/399707150
            return Err(am_err!(Unimplemented, "Non persistent instances are not yet supported."));
        };
        // Construct the connection state
        let connection_state = AuthenticatedConnectionState::new(
            Arc::clone(&auth_started_entry.instance_id),
            auth_started_entry.transport_id,
            instance_seq_number,
            DiceArtifacts {
                cert_chain: Arc::clone(&auth_started_entry.cert_chain),
                policy: given_dice_policy,
            },
            sig_verification_key,
            is_persistent,
            self.memory_limits.max_clients_per_pvm,
        )?;
        connection.store_authenticated_state(connection_state)?;
        auth_started_entry
            .mark_as_authenticated(&mut self.auth_started_pvms, &mut self.auth_completed_pvms)?;
        Ok(())
    }

    // A helper method for creating/updating the instance context in the secure storage and
    // enforcing rollback protection for a persistent pvm.
    fn handle_rollback_protection_for_persistent_instance(
        &mut self,
        instance_id: &InstanceIdentifier,
        given_policy: &Policy,
        dice_chain: &CertChain,
    ) -> Result<i32, Error> {
        match self.persistent_storage.read_instance_context(instance_id)? {
            Some(instance_ctx) => {
                self.enforce_rollback_protection_for_pvm(
                    instance_id,
                    given_policy,
                    &instance_ctx.dice_policy,
                    dice_chain,
                    true,
                )?;
                Ok(instance_ctx.sequence_number)
            }
            None => {
                if !self.device.is_persistent_instance_creation_allowed(instance_id, dice_chain)? {
                    return Err(am_err!(
                        InstanceContextCreationDenied,
                        "the given persistent instance cannot be created"
                    ));
                }
                let sequence_number = self
                    .latest_global_sequence_number
                    .fetch_and_increment(&mut *self.persistent_storage)?;
                self.persistent_storage.create_instance_context(
                    instance_id,
                    PersistentInstanceContext {
                        version: VERSION_PERSISTENT_INSTANCE_CONTEXT,
                        sequence_number,
                        dice_policy: given_policy.clone(),
                    },
                )?;
                Ok(sequence_number)
            }
        }
    }

    // A helper function for enforcing rollback protection on a pvm instance.
    fn enforce_rollback_protection_for_pvm(
        &mut self,
        instance_id: &InstanceIdentifier,
        given_policy: &Policy,
        stored_policy: &Policy,
        dice_chain: &CertChain,
        is_persistent: bool,
    ) -> Result<(), Error> {
        // First, match the given policy and the dice chain
        if !match_dice_chain_with_policy(dice_chain, given_policy)? {
            return Err(am_err!(
                DicePolicyMatchingFailed,
                "the DICE chain doesn't match the given DICE policy."
            ));
        }
        if stored_policy != given_policy {
            if !match_dice_chain_with_policy(dice_chain, stored_policy)? {
                return Err(am_err!(
                    DicePolicyMatchingFailed,
                    "the DICE chain doesn't match the stored DICE policy."
                ));
            }
            if is_persistent {
                self.persistent_storage
                    .update_instance_policy_in_storage(instance_id, given_policy)?;
            } else {
                // TODO: b/399707150
                return Err(am_err!(
                    Unimplemented,
                    "Non persistent instances are not yet supported."
                ));
            }
        }
        Ok(())
    }
}
