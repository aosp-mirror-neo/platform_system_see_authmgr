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
    data_structures::{
        AuthStartedPvms, AuthenticatedPvms, AuthorizedClientsGlobalList, MemoryLimits,
        PendingClientAuthorizations,
    },
    error::Error,
    traits::{CryptoTraitImpl, Device, PersistentStorage},
};
use alloc::boxed::Box;

/// Data structure encapsulating AuthMgr backend.
/// Note that we assume the use of AuthMgrBE in single threaded environments. It is planned for the
/// future to make AuthMgrBE usable in multi-threaded environments b/369207531.
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
}
