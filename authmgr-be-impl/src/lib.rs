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
use authmgr_be::traits::{Device, RawConnection};
use authmgr_common::{signed_connection_request::TransportID, CryptoTraitImpl};
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

    /// Connect to the trusted service identified by `service_name` and hand over the client
    /// connection along with the unique client id.
    fn handover_client_connection(
        &self,
        _service_name: &str,
        _client_seq_number: i64,
        _client_conn_handle: Box<dyn RawConnection>,
        _is_persistent: bool,
    ) -> Result<(), Error> {
        // The mock implementation cannot do connection handover
        Ok(())
    }

    /// Check whether the persistent instance with the given instance id and the dice cert chain is
    /// allowed to be created. Return true in the mock implementation of the trait.
    fn is_persistent_instance_creation_allowed(
        &self,
        _instance_id: &InstanceIdentifier,
        _dice_chain: &CertChain,
    ) -> Result<bool, Error> {
        Ok(true)
    }
}

#[cfg(test)]
mod tests;
