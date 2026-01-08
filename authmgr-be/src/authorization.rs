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
use crate::{
    am_err,
    data_structures::{
        AuthStartedPvm, AuthStartedPvms, AuthenticatedConnectionInfo, AuthenticatedPvms,
        AuthorizedClient, AuthorizedClientFullDiceArtifacts, AuthorizedClientsGlobalList, ClientId,
        ClientInfoAtRollbackProtection, ClientMetaData, ConnectionAuthState, DiceArtifacts,
        InstanceIdentifier, MemoryLimits, PendingClientAuthorization, PendingClientAuthorizations,
        PersistentClientContext, PersistentInstanceContext, PolicyMatchingResult,
        VERSION_PERSISTENT_CLIENT_CONTEXT, VERSION_PERSISTENT_INSTANCE_CONTEXT,
    },
    error::{Error, ErrorCode, PolicyMatchingError},
    traits::{Device, PersistentStorage, RawConnection, RpcConnection, WriteMode},
    try_to_vec,
};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use authgraph_core::key::{CertChain, DiceChainEntry};
use authmgr_common::{
    extend_dice_policy_with, match_dice_cert_with_policy, match_dice_chain_with_policy,
    signed_connection_request::{Challenge, ConnectionRequest},
    CryptoTraitImpl, DicePolicy, Token,
};
use coset::CborSerializable;
use log::error;

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
/// identifier to the instances and clients by the AuthMgr BE.
/// Currently, AIDL types do not support u64. Therefore, we use i64 here, although client sequence
/// number cannot be negative.
pub struct LatestGlobalSeqNum(i64);

impl LatestGlobalSeqNum {
    /// Constructs an instance of the in-memory global sequence number given the latest global
    /// sequence number which is read from the persistent storage
    pub fn new(latest_global_seq_num: i64) -> Self {
        Self(latest_global_seq_num)
    }

    /// Return the current global sequence number and increment the global sequence number in the
    /// persistent storage and in this in-memory instance
    pub fn fetch_and_increment(
        &mut self,
        persistent_storage: &mut dyn PersistentStorage,
    ) -> Result<i64, Error> {
        let current_global_seq_num = self.0;
        self.0 = increment_global_sequence_number(persistent_storage)?;
        Ok(current_global_seq_num)
    }
}

impl AuthMgrBE {
    /// Initialize AuthMgr BE
    pub fn new(
        crypto: CryptoTraitImpl,
        mut device: Box<dyn Device>,
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
            LatestGlobalSeqNum(get_or_create_global_sequence_number(&mut *persistent_storage)?);

        device.do_maintenance_during_boot(&mut *persistent_storage)?;

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
        connection: &mut dyn RpcConnection,
        cert_chain: &[u8],
        ext_instance_id: Option<&[u8]>,
    ) -> Result<Challenge, Error> {
        match connection.current_auth_state()? {
            ConnectionAuthState::None => (),
            ConnectionAuthState::AuthenticationStarted => {
                return Err(am_err!(
                    AuthenticationAlreadyStarted,
                    "connection is already started authentication"
                ));
            }
            ConnectionAuthState::AuthenticationCompleted(_) => {
                return Err(am_err!(
                    InstanceAlreadyAuthenticated,
                    "connection is already authenticated"
                ));
            }
        };

        // Retrieve the transport ID
        let transport_id = connection.get_peer_transport_id()?;

        // Decode the DICE certificate chain
        let cert_chain = CertChain::from_slice(cert_chain)
            .map_err(|_e| am_err!(InvalidDiceCertChain, "failed to decode the DICE cert chain."))?;

        // Check if an instance id is provided in the optional parameter. If it is not present,
        // extract the instance id from the DICE chain.
        let instance_id: InstanceIdentifier = match ext_instance_id {
            Some(instance_id) => InstanceIdentifier::try_new(instance_id)?,
            None => {
                return Err(am_err!(
                    InvalidInstanceIdentifier,
                    "Instance identifier is neither present in
                        the argument, nor in the DICE cert chain."
                ))
            }
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
        connection.set_current_auth_state(ConnectionAuthState::AuthenticationStarted);
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
        match connection.current_auth_state()? {
            ConnectionAuthState::None => {
                return Err(am_err!(
                    AuthenticationNotStarted,
                    "connection has not started authentication"
                ));
            }
            ConnectionAuthState::AuthenticationStarted => {}
            ConnectionAuthState::AuthenticationCompleted(_) => {
                return Err(am_err!(
                    InstanceAlreadyAuthenticated,
                    "connection is already authenticated"
                ));
            }
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

        let given_dice_policy = Arc::new(DicePolicy::from_slice(dice_policy).map_err(|e| {
            am_err!(InvalidDicePolicy, "failed to decode the DICE policy: {:?}", e)
        })?);

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

        let is_persistent = auth_started_entry.instance_id.is_persistent();
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
        let connection_state = AuthenticatedConnectionInfo::new(
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
        auth_started_entry
            .mark_as_authenticated(&mut self.auth_started_pvms, &mut self.auth_completed_pvms)?;
        connection.set_current_auth_state(ConnectionAuthState::AuthenticationCompleted(Box::new(
            connection_state,
        )));
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
        let state = match connection.current_mut_auth_state()? {
            ConnectionAuthState::AuthenticationCompleted(ref mut auth_state) => auth_state,
            _ => {
                return Err(am_err!(
                    ConnectionNotAuthenticated,
                    "phase 2 of the AuthMgr protocol can only be invoked on an authenticated connection."
                ));
            }
        };

        // Retrieve the new connection corresponding to this request from pending authorizations
        let pending_authorization =
            self.pending_client_authorizations.take(state.transport_id, token).ok_or(am_err!(
                NoConnectionToAuthorize,
                "no pending authorization found for the transport id: {:?} and token: {:?}",
                state.transport_id,
                token
            ))?;
        let given_policy = Arc::new(DicePolicy::from_slice(client_dice_policy).map_err(|e| {
            am_err!(InvalidDicePolicy, "failed to decode the DICE policy: {:?}", e)
        })?);
        let client_id = Arc::new(ClientId(try_to_vec(client_id)?));
        let given_dice_cert = DiceChainEntry::from_slice(client_dice_cert)?;
        let is_persistent = state.is_persistent;
        let instance_id = Arc::clone(&state.instance_id);
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
                    &instance_id,
                    instance_seq_number,
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
                        &instance_id,
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
        match connection.current_auth_state()? {
            ConnectionAuthState::None => {}
            ConnectionAuthState::AuthenticationStarted => {
                self.auth_started_pvms.remove_via_transport_id(transport_id);
            }
            ConnectionAuthState::AuthenticationCompleted(_) => {
                self.auth_completed_pvms.remove_via_transport_id(transport_id);
                self.pending_client_authorizations.remove_via_transport_id(transport_id);
                self.authorized_clients.remove_via_transport_id(transport_id);
                connection.set_current_auth_state(ConnectionAuthState::None);
            }
        }
        Ok(())
    }

    /// Retrieve the DICE policy for a client identified by the client sequence number, if the
    /// client sequence number is found in the AuthMgr-BE's in-memory list
    /// (i.e. AuthorizedClientsGlobalList).
    pub fn get_policy(&self, client_seq_number: i64) -> Result<Vec<u8>, PolicyMatchingError> {
        match self.authorized_clients.get(client_seq_number) {
            Some(client) => (*client.full_dice_artifacts.policy).clone().to_vec().map_err(|e| {
                error!("failed to encode the DICE policy: {:?}", e);
                PolicyMatchingError::InternalError
            }),
            None => Err(PolicyMatchingError::ClientSeqNumNotFound),
        }
    }

    /// Match a given policy against a client's latest DICE chain and compare the given policy with
    /// the client's latest policy. The
    pub fn match_policy(
        &self,
        client_seq_number: i64,
        given_policy: &[u8],
    ) -> Result<PolicyMatchingResult, PolicyMatchingError> {
        let given_policy = DicePolicy::from_slice(given_policy).map_err(|e| {
            error!("failed to decode the DICE policy: {:?}", e);
            PolicyMatchingError::InvalidDicePolicy
        })?;
        let client = self
            .authorized_clients
            .get(client_seq_number)
            .ok_or(PolicyMatchingError::ClientSeqNumNotFound)?;
        if !match_dice_chain_with_policy(&client.full_dice_artifacts.cert_chain, &given_policy)? {
            Ok(PolicyMatchingResult::Failed)
        } else if given_policy != *client.full_dice_artifacts.policy {
            Ok(PolicyMatchingResult::MatchedNotCurrent)
        } else {
            Ok(PolicyMatchingResult::Success)
        }
    }

    /// Retrieve metadata of a client identified by the client sequence number
    pub fn get_client_metadata(
        &self,
        client_seq_number: i64,
    ) -> Result<ClientMetaData, PolicyMatchingError> {
        match self.authorized_clients.get(client_seq_number) {
            Some(client) => Ok(ClientMetaData {
                instance_id: InstanceIdentifier(client.instance_id.0),
                client_id: ClientId(try_to_vec(&client.client_id.0)?),
                is_persistent: client.is_persistent,
            }),
            None => Err(PolicyMatchingError::ClientSeqNumNotFound),
        }
    }

    // A helper method for creating/updating the instance context in the secure storage and
    // enforcing rollback protection for a persistent pvm.
    fn handle_instance_in_persistent_storage(
        &mut self,
        instance_id: &Arc<InstanceIdentifier>,
        given_policy: &Arc<DicePolicy>,
        dice_chain: &CertChain,
    ) -> Result<i64, Error> {
        match read_persistent_instance_context(&*self.persistent_storage, instance_id)? {
            Some(mut instance_ctx) => {
                self.enforce_rollback_protection_for_pvm(
                    instance_id,
                    given_policy,
                    &mut instance_ctx,
                    dice_chain,
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
                write_persistent_instance_context(
                    &mut *self.persistent_storage,
                    instance_id,
                    &PersistentInstanceContext {
                        version: VERSION_PERSISTENT_INSTANCE_CONTEXT,
                        sequence_number,
                        dice_policy: Arc::clone(given_policy),
                    },
                )?;
                Ok(sequence_number)
            }
        }
    }

    // A helper function for enforcing rollback protection on a pvm instance.aa
    fn enforce_rollback_protection_for_pvm(
        &mut self,
        instance_id: &Arc<InstanceIdentifier>,
        given_policy: &Arc<DicePolicy>,
        instance_ctx: &mut PersistentInstanceContext,
        dice_chain: &CertChain,
    ) -> Result<(), Error> {
        // First, match the given policy and the dice chain
        if !match_dice_chain_with_policy(dice_chain, given_policy)? {
            return Err(am_err!(
                DicePolicyMatchingFailed,
                "the DICE chain doesn't match the given DICE policy."
            ));
        }
        let overridden_policy =
            self.device.override_stored_policy_for_instance(instance_id, &instance_ctx.dice_policy);
        let policy_for_validation: &DicePolicy = match &overridden_policy {
            Some(v) => v,
            None => &instance_ctx.dice_policy,
        };
        if *policy_for_validation != **given_policy {
            if !match_dice_chain_with_policy(dice_chain, policy_for_validation)? {
                return Err(am_err!(
                    DicePolicyMatchingFailed,
                    "the DICE chain doesn't match the stored DICE policy."
                ));
            }
            update_persistent_instance_policy(
                &mut *self.persistent_storage,
                instance_id,
                given_policy,
                instance_ctx,
            )?;
        }
        Ok(())
    }

    // A helper method to enforce rollback protection for a client already in the cache.
    fn enforce_rollback_protection_for_client_in_cache(
        &mut self,
        instance_id: &Arc<InstanceIdentifier>,
        instance_seq_number: i64,
        authorized_client: &mut AuthorizedClient,
        given_dice_cert: &DiceChainEntry,
        given_policy: &Arc<DicePolicy>,
    ) -> Result<(), Error> {
        self.enforce_rollback_protection_for_client(
            instance_id,
            instance_seq_number,
            &Arc::clone(&authorized_client.client_id),
            given_dice_cert,
            given_policy,
            &mut ClientInfoAtRollbackProtection::FromCache(authorized_client),
        )
    }

    fn handle_client_in_persistent_storage(
        &mut self,
        instance_id: &Arc<InstanceIdentifier>,
        instance_seq_number: i64,
        client_id: &Arc<ClientId>,
        given_dice_cert: &DiceChainEntry,
        given_policy: &Arc<DicePolicy>,
    ) -> Result<i64, Error> {
        match read_persistent_client_context(
            &*self.persistent_storage,
            instance_id,
            instance_seq_number,
            client_id,
        )? {
            Some(mut client_ctx) => {
                self.enforce_rollback_protection_for_client(
                    instance_id,
                    instance_seq_number,
                    client_id,
                    given_dice_cert,
                    given_policy,
                    &mut ClientInfoAtRollbackProtection::FromPersistentStorage(&mut client_ctx),
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
                write_persistent_client_context(
                    &mut *self.persistent_storage,
                    instance_id,
                    instance_seq_number,
                    client_id,
                    &PersistentClientContext {
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
        instance_id: &Arc<InstanceIdentifier>,
        instance_seq_number: i64,
        client_id: &Arc<ClientId>,
        given_dice_cert: &DiceChainEntry,
        given_policy: &Arc<DicePolicy>,
        client_info: &mut ClientInfoAtRollbackProtection,
    ) -> Result<(), Error> {
        // First, match the given policy and the DICE certificate
        if !match_dice_cert_with_policy(given_dice_cert, given_policy)? {
            return Err(am_err!(
                DicePolicyMatchingFailed,
                "the client's DICE leaf certificate doesn't match the given DICE policy"
            ));
        }
        let overridden_policy = self.device.override_stored_policy_for_client(
            instance_id,
            client_id,
            client_info.get_policy()?,
        );
        let policy_for_validation: &DicePolicy = match &overridden_policy {
            Some(v) => v,
            None => client_info.get_policy()?,
        };
        if *policy_for_validation != **given_policy {
            if !match_dice_cert_with_policy(given_dice_cert, policy_for_validation)? {
                return Err(am_err!(
                    DicePolicyMatchingFailed,
                    "the client's DICE leaf certificate doesn't match the stored DICE policy"
                ));
            }
            // Update the policy in the storage
            update_persistent_client_policy(
                &mut *self.persistent_storage,
                instance_id,
                instance_seq_number,
                client_id,
                given_policy,
                client_info,
            )?;
        }
        Ok(())
    }

    // We need to update the cache containing the global list of authorized clients with
    // their full DICE artifacts to be used in the service exposed by the AuthMgr BE to the
    // trusted services for matching DICE chain and DICE policies of the clients.
    fn update_global_list_of_authorized_clients(
        &mut self,
        state: &AuthenticatedConnectionInfo,
        client_seq_number: i64,
        client_id: &Arc<ClientId>,
        dice_leaf: &DiceChainEntry,
        given_policy: &Arc<DicePolicy>,
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
                    instance_id: Arc::clone(&state.instance_id),
                    is_persistent: state.is_persistent,
                })?;
            }
        }
        Ok(())
    }
}

// A helper function to read the global sequence number from the persistent storage. If reading for
// the first time, initialize the global sequence number to zero.
fn get_or_create_global_sequence_number(
    persistent_storage: &mut dyn PersistentStorage,
) -> Result<i64, Error> {
    persistent_storage.read(persistent_storage.get_global_seq_num_storage_path())?.map_or_else(
        || {
            let global_seq_num_init: i64 = 0;
            persistent_storage.write(
                persistent_storage.get_global_seq_num_storage_path(),
                &global_seq_num_init.to_ne_bytes(),
                WriteMode::CreateExclusive,
            )?;
            Ok(global_seq_num_init)
        },
        |v| {
            let seq_num = i64::from_ne_bytes(v.as_slice().try_into()?);
            Ok(seq_num)
        },
    )
}

// A helper function to increment the  global sequence number in the persistent storage, using the
// storage trait's methods.
fn increment_global_sequence_number(
    persistent_storage: &mut dyn PersistentStorage,
) -> Result<i64, Error> {
    let current = persistent_storage
        .read(persistent_storage.get_global_seq_num_storage_path())?
        .map_or_else(
            || Err(am_err!(InternalError, "global sequence number is not initialized")),
            |v| Ok::<i64, Error>(i64::from_ne_bytes(v.as_slice().try_into()?)),
        )?;
    let incremented = current + 1;
    persistent_storage.write(
        persistent_storage.get_global_seq_num_storage_path(),
        &incremented.to_ne_bytes(),
        WriteMode::OverwriteExisting,
    )?;
    Ok(incremented)
}

// A helper function to write a new instance context to the persistent storage.
fn write_persistent_instance_context(
    storage: &mut dyn PersistentStorage,
    instance_id: &Arc<InstanceIdentifier>,
    instance_ctx: &PersistentInstanceContext,
) -> Result<(), Error> {
    let path = storage.build_storage_file_path_for_instance(instance_id);
    let ctx_bytes = instance_ctx.to_bytes()?;
    storage.write(&path, ctx_bytes.as_slice(), WriteMode::CreateExclusive)
}

// A helper function to read the instance context from the persistent storage.
fn read_persistent_instance_context(
    storage: &dyn PersistentStorage,
    instance_id: &Arc<InstanceIdentifier>,
) -> Result<Option<PersistentInstanceContext>, Error> {
    let path = storage.build_storage_file_path_for_instance(instance_id);
    storage
        .read(&path)?
        .map_or_else(|| Ok(None), |data| Ok(Some(PersistentInstanceContext::from_bytes(&data)?)))
}

// A helper function to update the instance's DICE policy in the persistent storage.
fn update_persistent_instance_policy(
    storage: &mut dyn PersistentStorage,
    instance_id: &Arc<InstanceIdentifier>,
    latest_dice_policy: &Arc<DicePolicy>,
    instance_ctx: &mut PersistentInstanceContext,
) -> Result<(), Error> {
    let path = storage.build_storage_file_path_for_instance(instance_id);
    instance_ctx.dice_policy = Arc::clone(latest_dice_policy);
    let ctx_bytes = instance_ctx.to_bytes()?;
    storage.write(&path, ctx_bytes.as_slice(), WriteMode::OverwriteExisting)
}

// A helper function to write a new client context to the persistent storage.
fn write_persistent_client_context(
    storage: &mut dyn PersistentStorage,
    instance_id: &Arc<InstanceIdentifier>,
    instance_seq_number: i64,
    client_id: &Arc<ClientId>,
    client_ctx: &PersistentClientContext,
) -> Result<(), Error> {
    let path =
        storage.build_storage_file_path_for_client(instance_id, instance_seq_number, client_id);
    let ctx_bytes = client_ctx.to_bytes()?;
    storage.write(&path, ctx_bytes.as_slice(), WriteMode::CreateExclusive)
}

// A helper function to read the client context from the persistent storage.
fn read_persistent_client_context(
    storage: &dyn PersistentStorage,
    instance_id: &Arc<InstanceIdentifier>,
    instance_seq_number: i64,
    client_id: &Arc<ClientId>,
) -> Result<Option<PersistentClientContext>, Error> {
    let path =
        storage.build_storage_file_path_for_client(instance_id, instance_seq_number, client_id);
    storage
        .read(&path)?
        .map_or_else(|| Ok(None), |data| Ok(Some(PersistentClientContext::from_bytes(&data)?)))
}

// A helper function to update the client's DICE policy in the persistent storage.
fn update_persistent_client_policy(
    storage: &mut dyn PersistentStorage,
    instance_id: &Arc<InstanceIdentifier>,
    instance_seq_number: i64,
    client_id: &Arc<ClientId>,
    latest_dice_policy: &Arc<DicePolicy>,
    client_info: &mut ClientInfoAtRollbackProtection,
) -> Result<(), Error> {
    match client_info {
        ClientInfoAtRollbackProtection::FromPersistentStorage(client_ctx) => {
            let path = storage.build_storage_file_path_for_client(
                instance_id,
                instance_seq_number,
                client_id,
            );
            client_ctx.dice_policy = Arc::clone(latest_dice_policy);
            let ctx_bytes = client_ctx.to_bytes()?;
            storage.write(&path, ctx_bytes.as_slice(), WriteMode::OverwriteExisting)
        }
        ClientInfoAtRollbackProtection::FromCache(authorized_client) => {
            let path = storage.build_storage_file_path_for_client(
                instance_id,
                instance_seq_number,
                client_id,
            );
            let mut client_ctx = read_persistent_client_context(
                storage,
                instance_id,
                instance_seq_number,
                client_id,
            )?
            .ok_or(am_err!(
                InternalError,
                "storage not found for client context at: {:?}",
                path
            ))?;
            client_ctx.dice_policy = Arc::clone(latest_dice_policy);
            let ctx_bytes = client_ctx.to_bytes()?;
            storage.write(&path, ctx_bytes.as_slice(), WriteMode::OverwriteExisting)?;
            authorized_client.update_policy(latest_dice_policy);
            Ok(())
        }
    }
}
