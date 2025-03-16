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

//! Crate containing the example/mock implementations of some of the AuthMgr BE traits for testing
//! purposes. These are the traits that can be implemented (mostly) independent of a concrete
//! AuthMgr TA running in the TEE environment. For e.g. Crypto traits, Device trait (without the
//! connection handover functionality) and the *Storage traits.
//! This crate calls into the generic tests provided by the `libauthmgr_be_test` crate in order to
//! run unit tests using the aforementioned (example) trait implementations.
extern crate alloc;
use authgraph_boringssl::{ec::BoringEcDsa, BoringRng};
use authgraph_core::key::{CertChain, InstanceIdentifier, Policy};
use authmgr_be::error::Error;
use authmgr_be::traits::{CryptoTraitImpl, Device, RawConnection};
use authmgr_common::{match_dice_chain_with_policy, signed_connection_request::TransportID};
use std::collections::HashMap;

pub mod mock_storage;

/// Return a populated [`CryptoTraitImpl`] structure that uses BoringSSL implementations for
/// cryptographic traits.
pub fn crypto_trait_impls() -> CryptoTraitImpl {
    CryptoTraitImpl { ecdsa: Box::new(BoringEcDsa), rng: Box::new(BoringRng) }
}

/// Struct representing the state used to provide a mock implementation of AuthMgr `Device`` trait
#[derive(Default)]
pub struct AuthMgrBeDevice {
    /// Transport ID of AuthMgr BE
    pub transport_id: TransportID,
    /// List of persistent instances allowed along with the DICE policies.
    pub allowed_persistent_instances: HashMap<InstanceIdentifier, Policy>,
}

impl AuthMgrBeDevice {
    /// Constructor
    pub fn new(
        transport_id: TransportID,
        allowed_persistent_instances: HashMap<InstanceIdentifier, Policy>,
    ) -> Self {
        Self { transport_id, allowed_persistent_instances }
    }
}

impl Device for AuthMgrBeDevice {
    /// Return the transport ID of the AuthMgr BE
    fn get_self_transport_id(&self) -> Result<TransportID, Error> {
        Ok(self.transport_id)
    }

    /// Secure storage invariant: we cannot allow a non-persistent pVM connect to secure storage
    /// without the secure storage knowing that it is a non-persistent client. Therefore, the
    /// AuthMgr BE should know whether a given pVM is persistent. In the first version of the
    /// trusted HAL project, we only support persistent pVM clients, therefore, in the first
    /// version, this could simply return true. When non-persistent pVMs are supported, it is
    /// expected that the AuthMgr BE learns via some out-of-band mechanism the instance ids of the
    /// peristence pVMs on the device.
    fn is_persistent_instance(&self, instance_id: &InstanceIdentifier) -> Result<bool, Error> {
        Ok(self.allowed_persistent_instances.contains_key(instance_id))
    }

    /// Connect to the trusted service identified by `service_name` and hand over the client
    /// connection along with the unique client id.
    fn handover_client_connection(
        &self,
        _service_name: &str,
        _client_seq_number: i32,
        _client_conn_handle: Box<dyn RawConnection>,
        _is_persistent: bool,
    ) -> Result<(), Error> {
        // The mock implementation cannot do connection handover
        Ok(())
    }

    /// Check whether the persistent instance with the given instance id and the dice cert chain is
    /// allowed to be created.s
    fn is_persistent_instance_creation_allowed(
        &self,
        instance_id: &InstanceIdentifier,
        dice_chain: &CertChain,
    ) -> Result<bool, Error> {
        Ok(match_dice_chain_with_policy(
            dice_chain,
            self.allowed_persistent_instances.get(instance_id).unwrap(),
        )?)
    }
}

#[cfg(test)]
mod tests;
