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
        AuthorizedClient, AuthorizedClientFullDiceArtifacts, AuthorizedClientsGlobalList, ClientId,
        DiceArtifacts, MemoryLimits, PendingClientAuthorization, PendingClientAuthorizations,
        PersistentClientContext, PersistentInstanceContext, VERSION_PERSISTENT_CLIENT_CONTEXT,
        VERSION_PERSISTENT_INSTANCE_CONTEXT,
    },
    error::{Error, ErrorCode},
    traits::{CryptoTraitImpl, Device, PersistentStorage, RawConnection, RpcConnection},
    try_to_vec,
};
use alloc::boxed::Box;
use alloc::sync::Arc;
use authgraph_core::key::{CertChain, DiceChainEntry, InstanceIdentifier, Policy};
use authmgr_common::{
    extend_dice_policy_with, match_dice_cert_with_policy, match_dice_chain_with_policy,
    signed_connection_request::{Challenge, ConnectionRequest},
    Token,
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
        let cert_chain = CertChain::from_slice(cert_chain)
            .map_err(|_e| am_err!(InvalidDiceCertChain, "failed to decode the DICE cert chain."))?;

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
        // Check for duplicated authentication attempts to enforce Trust On First Use (TOFU).
        if self.auth_completed_pvms.has_transport_id(peer_transport_id) {
            return Err(am_err!(
                InstanceAlreadyAuthenticated,
                "duplicated authentication attempt!"
            ));
        }
        let auth_started_entry =
            self.auth_started_pvms.take_via_transport_id(peer_transport_id).ok_or(am_err!(
                AuthenticationNotStarted,
                "An authentication started pVM was not found for the given transport id"
            ))?;
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

        let given_dice_policy = Arc::new(Policy(try_to_vec(dice_policy)?));
        let is_persistent = self.device.is_persistent_instance(&auth_started_entry.instance_id)?;
        let instance_seq_number = if is_persistent {
            self.handle_instance_in_persistent_storage(
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

    /// Step 1 of phase 2
    /// A new connection should be used for client authorization. The AuthMgr-BE TA implementation
    /// should make sure that it fails gracefully, if a connection that is already used for instance
    /// authentication is attempted to be used for client authorization.
    pub fn init_connection_for_client(
        &mut self,
        client_connection: Box<dyn RawConnection>,
        token: Token,
    ) -> Result<(), Error> {
        // Check if this request comes from a pVM which has an AuthMgr FE that is already
        // authenticated with the AuthMgr BE.
        let client_transport_id = client_connection.get_peer_transport_id()?;
        if !self.auth_completed_pvms.has_transport_id(client_transport_id) {
            return Err(am_err!(
                InstanceNotAuthenticated,
                "the transport id is not associated with a pVM that has an
                  authenticated AuthMgr FE."
            ));
        }

        // Add the connection and the token to the pending client authorization list.
        self.pending_client_authorizations
            .insert(client_transport_id, PendingClientAuthorization { token, client_connection })?;
        Ok(())
    }

    /// Step 2 of phase 2
    pub fn authorize_and_connect_client_to_trusted_service(
        &mut self,
        connection: &mut dyn RpcConnection,
        client_id: &[u8],
        service_name: &str,
        token: Token,
        client_dice_cert: &[u8],
        client_dice_policy: &[u8],
    ) -> Result<(), Error> {
        // Check whether the connection is already authenticated.
        let state = connection.get_mutable_authenticated_state()?.ok_or(am_err!(
            ConnectionNotAuthenticated,
            "phase 2 of the AuthMgr protocol can only be invoked on an authenticated connection."
        ))?;
        // Retrieve the new connection corresponding to this request from pending authorizations
        let pending_authorization =
            self.pending_client_authorizations.take(state.transport_id, token).ok_or(am_err!(
                NoConnectionToAuthorize,
                "no pending authorization found for the transport id: {:?} and token: {:?}",
                state.transport_id,
                token
            ))?;

        let client_id = Arc::new(ClientId(try_to_vec(client_id)?));
        let given_policy = Arc::new(Policy(try_to_vec(client_dice_policy)?));
        let given_dice_cert = DiceChainEntry::from_slice(client_dice_cert)?;
        let is_persistent = state.is_persistent;
        let instance_seq_number = state.instance_seq_number;
        // In what follows, we do the following:
        // 1. Read from the cache to see if this client is already authorized in the current boot
        //    cycle of the pVM instance. If the client is in the cache, enforce rollback protection
        //    for the client in the cache. This includes running the dice chain to policy matching
        //    checks and if they are successful, updating both the storage and the cache if the
        //    policy has been updated.
        // 2. If the client is not in the cache, read the client context from the storage.
        //    a) If the client context is in the storage, enforce rollback protection for the client
        //       in the storage.
        //    b) If the client is not in the stroge, create the instance context in the storage.
        //    c) Insert the client into the cache.
        let mut authorized_client = state.get_mutable_authorized_client(&client_id);
        let (client_seq_number, policy_need_update) = match authorized_client {
            Some(ref mut client) => {
                let client_seq_number = client.sequence_number;
                let policy_need_update = !(given_policy == client.policy);
                self.enforce_rollback_protection_for_client_in_cache(
                    instance_seq_number,
                    is_persistent,
                    client,
                    &given_dice_cert,
                    &given_policy,
                )?;
                (client_seq_number, policy_need_update)
            }
            None => {
                // If not, read from the storage
                let client_seq_number = if is_persistent {
                    self.handle_client_in_persistent_storage(
                        instance_seq_number,
                        &client_id,
                        &given_dice_cert,
                        &given_policy,
                    )?
                } else {
                    // TODO: b/399707150
                    return Err(am_err!(
                        Unimplemented,
                        "Non persistent instances are not yet supported."
                    ));
                };
                // Insert into the cache
                state.insert_authorized_client(AuthorizedClient {
                    client_id: Arc::clone(&client_id),
                    sequence_number: client_seq_number,
                    policy: Arc::clone(&given_policy),
                })?;
                (client_seq_number, false)
            }
        };
        // Update the cache containing the global list of authorized clients with their full DICE
        // artifacts to be used by the "policy matching as a service" offered by AuthMgr-BE
        self.update_global_list_of_authorized_clients(
            state,
            client_seq_number,
            &client_id,
            &given_dice_cert,
            &given_policy,
            policy_need_update,
        )?;
        // Handover the authorized client to the requested trusted service
        // TODO: Upon successful handover, update the connected services for the client in the cache
        // and the storage, if needed
        self.device.handover_client_connection(
            service_name,
            client_seq_number,
            pending_authorization.client_connection,
            is_persistent,
        )
    }

    /// This should be called by the TEE environment upon closing of every connection established
    /// between AuthMgr FE and AuthMgr BE "for the purpose of authenticating AuthMgr FE
    /// to AuthMgr BE" - i.e. the connections established in phase 1, in order to clear the cache.
    pub fn clear_cache_upon_main_connection_close(
        &mut self,
        connection: &mut dyn RpcConnection,
    ) -> Result<(), Error> {
        let transport_id = connection.get_peer_transport_id()?;
        self.auth_started_pvms.remove_via_transport_id(transport_id);
        self.auth_completed_pvms.remove_via_transport_id(transport_id);
        self.pending_client_authorizations.remove_via_transport_id(transport_id);
        self.authorized_clients.remove_via_transport_id(transport_id);
        connection.remove_authenticated_state()?;
        Ok(())
    }

    // A helper method for creating/updating the instance context in the secure storage and
    // enforcing rollback protection for a persistent pvm.
    fn handle_instance_in_persistent_storage(
        &mut self,
        instance_id: &Arc<InstanceIdentifier>,
        given_policy: &Arc<Policy>,
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
                if !match_dice_chain_with_policy(dice_chain, given_policy)? {
                    return Err(am_err!(
                        DicePolicyMatchingFailed,
                        "the DICE chain doesn't match the given DICE policy."
                    ));
                }
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
                        dice_policy: Arc::clone(given_policy),
                    },
                )?;
                Ok(sequence_number)
            }
        }
    }

    // A helper function for enforcing rollback protection on a pvm instance.
    fn enforce_rollback_protection_for_pvm(
        &mut self,
        instance_id: &Arc<InstanceIdentifier>,
        given_policy: &Arc<Policy>,
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
        if *stored_policy != **given_policy {
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

    // A helper method to enforce rollback protection for a client already in the cache.
    fn enforce_rollback_protection_for_client_in_cache(
        &mut self,
        instance_seq_number: i32,
        is_persistent: bool,
        authorized_client: &mut AuthorizedClient,
        given_dice_cert: &DiceChainEntry,
        given_policy: &Arc<Policy>,
    ) -> Result<(), Error> {
        self.enforce_rollback_protection_for_client(
            instance_seq_number,
            &authorized_client.client_id,
            given_dice_cert,
            given_policy,
            &authorized_client.policy,
            is_persistent,
        )?;
        if *authorized_client.policy != **given_policy {
            // Update the policy in the cache as well
            authorized_client.update_policy(given_policy);
        }
        Ok(())
    }

    fn handle_client_in_persistent_storage(
        &mut self,
        instance_seq_number: i32,
        client_id: &Arc<ClientId>,
        given_dice_cert: &DiceChainEntry,
        given_policy: &Arc<Policy>,
    ) -> Result<i32, Error> {
        match self.persistent_storage.read_client_context(instance_seq_number, client_id)? {
            Some(client_ctx) => {
                self.enforce_rollback_protection_for_client(
                    instance_seq_number,
                    client_id,
                    given_dice_cert,
                    given_policy,
                    &client_ctx.dice_policy,
                    true,
                )?;
                Ok(client_ctx.sequence_number)
            }
            None => {
                if !match_dice_cert_with_policy(given_dice_cert, given_policy)? {
                    return Err(am_err!(
                        DicePolicyMatchingFailed,
                        "the client's DICE leaf certificate doesn't match the given DICE policy"
                    ));
                }
                let sequence_number = self
                    .latest_global_sequence_number
                    .fetch_and_increment(&mut *self.persistent_storage)?;
                self.persistent_storage.create_client_context(
                    instance_seq_number,
                    client_id,
                    PersistentClientContext {
                        version: VERSION_PERSISTENT_CLIENT_CONTEXT,
                        sequence_number,
                        dice_policy: Arc::clone(given_policy),
                    },
                )?;
                Ok(sequence_number)
            }
        }
    }

    fn enforce_rollback_protection_for_client(
        &mut self,
        instance_seq_number: i32,
        client_id: &Arc<ClientId>,
        given_dice_cert: &DiceChainEntry,
        given_policy: &Arc<Policy>,
        stored_policy: &Policy,
        is_persistent: bool,
    ) -> Result<(), Error> {
        // First, match the given policy and the DICE certificate
        if !match_dice_cert_with_policy(given_dice_cert, given_policy)? {
            return Err(am_err!(
                DicePolicyMatchingFailed,
                "the client's DICE leaf certificate doesn't match the given DICE policy"
            ));
        }
        if **given_policy != *stored_policy {
            if !match_dice_cert_with_policy(given_dice_cert, stored_policy)? {
                return Err(am_err!(
                    DicePolicyMatchingFailed,
                    "the client's DICE leaf certificate doesn't match the stored DICE policy"
                ));
            }
            // Update the policy in the storage
            if is_persistent {
                self.persistent_storage.update_client_policy_in_storage(
                    instance_seq_number,
                    client_id,
                    given_policy,
                )?;
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

    // We need to update the cache containing the global list of authorized clients with
    // their full DICE artifacts to be used in the service exposed by the AuthMgr BE to the
    // trusted services for matching DICE chain and DICE policies of the clients.
    fn update_global_list_of_authorized_clients(
        &mut self,
        state: &AuthenticatedConnectionState,
        client_seq_number: i32,
        client_id: &Arc<ClientId>,
        dice_leaf: &DiceChainEntry,
        given_policy: &Arc<Policy>,
        policy_need_update: bool,
    ) -> Result<(), Error> {
        match self.authorized_clients.get_mut(client_seq_number) {
            Some(ref mut authorized_client) => {
                if !authorized_client.full_dice_artifacts.cert_chain.is_current_leaf(dice_leaf) {
                    // This state is possible only if the client's DICE cert can change in runtime
                    // e.g. (loadable TAs)
                    let updated_full_dice_chain = (*state.dice_artifacts.cert_chain)
                        .extend_with(dice_leaf, &*self.crypto.ecdsa)?;
                    authorized_client.full_dice_artifacts.cert_chain =
                        Arc::new(updated_full_dice_chain);
                }

                if policy_need_update {
                    authorized_client.full_dice_artifacts.policy = Arc::new(
                        extend_dice_policy_with(&state.dice_artifacts.policy, given_policy)?,
                    );
                }
            }
            None => {
                let client_full_dice_artifacts = DiceArtifacts {
                    cert_chain: Arc::new(
                        (*state.dice_artifacts.cert_chain)
                            .extend_with(dice_leaf, &*self.crypto.ecdsa)?,
                    ),
                    policy: Arc::new(extend_dice_policy_with(
                        &state.dice_artifacts.policy,
                        given_policy,
                    )?),
                };

                self.authorized_clients.insert(AuthorizedClientFullDiceArtifacts {
                    sequence_number: client_seq_number,
                    transport_id: state.transport_id,
                    client_id: Arc::clone(client_id),
                    full_dice_artifacts: client_full_dice_artifacts,
                })?;
            }
        }
        Ok(())
    }
}
