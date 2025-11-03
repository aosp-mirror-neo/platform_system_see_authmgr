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

//! Module that implements a session for accessing the secure storage
use crate::error::{file_op_error_to_storage_error, Result};
use crate::file::File;
use alloc::string::String;
use alloc::vec::Vec;
use android_hardware_security_see_storage::aidl::android::hardware::security::see::storage::{
    Availability::Availability, Filesystem::Filesystem, ISecureStorage::ISecureStorage,
    IStorageSession::IStorageSession, Integrity::Integrity, OpenOptions::OpenOptions,
};
use android_hardware_security_see_storage::binder::Strong;
use log::{debug, trace};

/// Secure storage service name
pub const DEFAULT_SECURE_STORAGE_SERVICE_NAME: &str =
    "android.hardware.security.see.storage.ISecureStorage/default";

/// A tamper-proof filesystem.
pub const TAMPER_PROOF_EARLY_ACCESS_PERSISTENT_FS: Filesystem = Filesystem {
    integrity: Integrity::TAMPER_PROOF_AT_REST,
    availability: Availability::BEFORE_USERDATA,
    persistent: true,
};

/// Encapsulate a secure storage session
pub struct Session {
    inner: Strong<dyn IStorageSession>,
}

impl Session {
    /// Connect to the ISecureStorage and create a storage session, given a binder object of
    /// an `ISecureStorage`. This constructor takes the binder object as input, because creating
    /// a binder (RPC) connection to `ISecureStorage` can be vendor specific.
    pub fn new(
        storage_binder: &Strong<dyn ISecureStorage>,
        file_system: &Filesystem,
    ) -> Result<Self> {
        trace!("connecting to secure storage service...");
        let inner = storage_binder.startSession(file_system)?;
        debug!("successfully connected to secure storage service.");
        Ok(Session { inner })
    }

    /// Use this function to explicitly close the session before the session object goes out of
    /// scope
    pub fn close(self) {}

    /// Opens a file with the given path and options
    ///
    /// The returned `File` is tied to the lifetime of this session, ensuring it
    /// cannot outlive the transaction it belongs to.
    pub fn open_file<'a>(&'a self, path: &str, options: &OpenOptions) -> Result<File<'a>> {
        let file = self
            .inner
            .openFile(path, options)
            .map_err(|status| file_op_error_to_storage_error(status, path))?;
        Ok(File::new(file, self))
    }

    /// Deletes a file.
    pub fn delete_file(&self, path: &str) -> Result<()> {
        self.inner.deleteFile(path).map_err(|status| file_op_error_to_storage_error(status, path))
    }

    /// Lists all filenames in the given directory path.
    ///
    /// This method handles the pagination of the underlying `IDir` interface,
    /// returning a complete list of all files in the directory.
    pub fn list_files_in_dir(&self, path: &str) -> Result<Vec<String>> {
        trace!("Listing files in directory: {path}");
        let dir = self
            .inner
            .openDir(path)
            .map_err(|status| file_op_error_to_storage_error(status, path))?;

        let mut all_filenames = Vec::new();
        loop {
            // A maxCount of 0 signifies no limit.
            let filenames = dir.readNextFilenames(0)?;
            if filenames.is_empty() {
                break;
            }
            all_filenames.try_reserve(filenames.len())?;
            all_filenames.extend(filenames);
        }

        debug!("Found {path} files in directory '{}'", all_filenames.len());
        Ok(all_filenames)
    }

    /// Commit changes
    pub fn commit(&self) -> Result<()> {
        Ok(self.inner.commitChanges()?)
    }
}
