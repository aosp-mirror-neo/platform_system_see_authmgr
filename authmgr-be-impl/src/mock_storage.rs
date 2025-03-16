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

//! In-memory implementation of the storage trait for the purpose of unit-tests
// TODO: remove this
#![allow(dead_code)]
#![allow(unused_variables)]
use alloc::sync::Arc;
use authgraph_core::key::{InstanceIdentifier, Policy};
use authmgr_be::data_structures::{ClientId, PersistentClientContext, PersistentInstanceContext};
use authmgr_be::traits::{PersistentStorage, Storage};
use authmgr_be::{
    am_err,
    error::{Error, ErrorCode},
};
use std::collections::{hash_map::Entry, HashMap};

/// Instance sequence number is part of the fully qualified path of a client's storage
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct InstanceSeqNumber(i32);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct FullyQualifiedClientId(InstanceSeqNumber, Arc<ClientId>);

/// In-memory implementation for AuthMgr persistent storage
#[derive(Default)]
pub struct MockPersistentStorage {
    global_seq_num: i32,
    instances: HashMap<Arc<InstanceIdentifier>, PersistentInstanceContext>,
    clients: HashMap<FullyQualifiedClientId, PersistentClientContext>,
}

impl MockPersistentStorage {
    /// Constructor for `MockPersistentStorage`
    pub fn new() -> Self {
        Self { global_seq_num: 0, instances: HashMap::new(), clients: HashMap::new() }
    }
}

impl Storage for MockPersistentStorage {
    type InstanceContext = PersistentInstanceContext;
    type ClientContext = PersistentClientContext;

    fn update_instance_policy_in_storage(
        &mut self,
        instance_id: &Arc<InstanceIdentifier>,
        latest_dice_policy: &Arc<Policy>,
    ) -> Result<(), Error> {
        let instance = self
            .instances
            .get_mut(instance_id)
            .ok_or(am_err!(InternalError, "instance does not exist."))?;
        instance.dice_policy = Arc::clone(latest_dice_policy);
        Ok(())
    }

    fn update_client_policy_in_storage(
        &mut self,
        instance_seq_number: i32,
        client_id: &Arc<ClientId>,
        latest_dice_policy: &Arc<Policy>,
    ) -> Result<(), Error> {
        let client = self
            .clients
            .get_mut(&FullyQualifiedClientId(
                InstanceSeqNumber(instance_seq_number),
                Arc::clone(client_id),
            ))
            .ok_or(am_err!(InternalError, "client does not exist"))?;
        client.dice_policy = Arc::clone(latest_dice_policy);
        Ok(())
    }

    fn read_instance_context(
        &self,
        instance_id: &Arc<InstanceIdentifier>,
    ) -> Result<Option<Self::InstanceContext>, Error> {
        Ok(self.instances.get(instance_id).cloned())
    }

    fn create_instance_context(
        &mut self,
        instance_id: &Arc<InstanceIdentifier>,
        instance_info: Self::InstanceContext,
    ) -> Result<(), Error> {
        if let Entry::Vacant(e) = self.instances.entry(Arc::clone(instance_id)) {
            e.insert(instance_info);
            Ok(())
        } else {
            Err(am_err!(InternalError, "instance already exists"))
        }
    }

    fn read_client_context(
        &self,
        instance_seq_number: i32,
        client_id: &Arc<ClientId>,
    ) -> Result<Option<Self::ClientContext>, Error> {
        Ok(self
            .clients
            .get(&FullyQualifiedClientId(
                InstanceSeqNumber(instance_seq_number),
                Arc::clone(client_id),
            ))
            .cloned())
    }

    fn create_client_context(
        &mut self,
        instance_seq_number: i32,
        client_id: &Arc<ClientId>,
        client_info: Self::ClientContext,
    ) -> Result<(), Error> {
        if let Entry::Vacant(e) = self.clients.entry(FullyQualifiedClientId(
            InstanceSeqNumber(instance_seq_number),
            Arc::clone(client_id),
        )) {
            e.insert(client_info);
            Ok(())
        } else {
            Err(am_err!(InternalError, "client already exists"))
        }
    }
}

impl PersistentStorage for MockPersistentStorage {
    fn get_or_create_global_sequence_number(&mut self) -> Result<i32, Error> {
        Ok(self.global_seq_num)
    }

    fn increment_global_sequence_number(&mut self) -> Result<i32, Error> {
        self.global_seq_num += 1;
        Ok(self.global_seq_num)
    }
}
