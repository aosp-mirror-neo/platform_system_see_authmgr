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
use authmgr_be::traits::{PersistentStorage, Storage, WriteMode};
use authmgr_be::{
    am_err,
    error::{Error, ErrorCode},
    try_to_vec,
};
use std::collections::{hash_map::Entry, HashMap};

/// In-memory implementation for AuthMgr persistent storage
#[derive(Default)]
pub struct MockPersistentStorage {
    storage: HashMap<String, Vec<u8>>,
}

impl MockPersistentStorage {
    /// Constructor for `MockPersistentStorage`
    pub fn new() -> Self {
        Self { storage: HashMap::new() }
    }
}

impl Storage for MockPersistentStorage {
    fn read(&self, file_path: &str) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.storage.get(&String::from(file_path)).map(|v| v.to_vec()))
    }

    fn write(&mut self, file_path: &str, data: &[u8], write_mode: WriteMode) -> Result<(), Error> {
        match write_mode {
            WriteMode::CreateExclusive => {
                if let Entry::Vacant(e) = self.storage.entry(String::from(file_path)) {
                    e.insert(try_to_vec(data)?);
                    Ok(())
                } else {
                    Err(am_err!(
                        InternalError,
                        "storage already exists for the given file path {:?}",
                        file_path
                    ))
                }
            }
            WriteMode::OverwriteExisting => {
                if let Entry::Occupied(mut e) = self.storage.entry(String::from(file_path)) {
                    e.insert(try_to_vec(data)?);
                    Ok(())
                } else {
                    Err(am_err!(
                        InternalError,
                        "storage not found for the given file path {:?}",
                        file_path
                    ))
                }
            }
        }
    }
}

impl PersistentStorage for MockPersistentStorage {}
