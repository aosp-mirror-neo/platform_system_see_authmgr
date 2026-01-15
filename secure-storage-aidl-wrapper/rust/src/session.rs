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
use crate::error::{file_op_error_to_storage_error, Error, Result};
use crate::file::{File, OPEN_EXISTING_FOR_READ_ONLY};
use alloc::string::String;
use alloc::vec::Vec;
use android_hardware_security_see_storage::aidl::android::hardware::security::see::storage::{
    CreationMode::CreationMode, Filesystem::Filesystem, ISecureStorage::ISecureStorage,
    IStorageSession::IStorageSession, OpenOptions::OpenOptions,
};
use android_hardware_security_see_storage::binder::Strong;
use cfg_if::cfg_if;
use core::sync::atomic::{AtomicBool, Ordering};
use log::{debug, trace, warn};

/// Secure storage service name
pub const DEFAULT_SECURE_STORAGE_SERVICE_NAME: &str =
    "android.hardware.security.see.storage.ISecureStorage/default";

/// Encapsulate a secure storage session
pub struct Session {
    inner: Strong<dyn IStorageSession>,
    /// Tracks if any write operations (e.g., `write`, `delete_file`)
    /// have been performed during this session. This is thread-safe.
    is_dirty: AtomicBool,
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
        Ok(Session { inner, is_dirty: AtomicBool::new(false) })
    }

    /// Uses this function to explicitly close the session before the session object goes out of
    /// scope. This function commits any pending changes before the session is destroyed.
    pub fn close(self) -> Result<()> {
        self.commit()?;
        Ok(())
    }

    /// Opens a file with the given path and options
    ///
    /// The returned `File` is tied to the lifetime of this session, ensuring it
    /// cannot outlive the transaction it belongs to.
    pub fn open_file<'a>(&'a self, path: &str, options: &OpenOptions) -> Result<File<'a>> {
        // If the file is being created or truncated, the filesystem state changes immediately.
        // We must mark the session as dirty so these changes are committed.
        let modifies_fs = options.truncateOnOpen || options.createMode != CreationMode::NO_CREATE;
        let file = self
            .inner
            .openFile(path, options)
            .map_err(|status| file_op_error_to_storage_error(status, path))?;
        if modifies_fs {
            self.mark_dirty();
        }
        Ok(File::new(file, self))
    }

    /// Deletes a file.
    pub fn delete_file(&self, path: &str) -> Result<()> {
        self.inner
            .deleteFile(path)
            .map_err(|status| file_op_error_to_storage_error(status, path))?;
        self.mark_dirty();
        Ok(())
    }

    /// Reads the entire content of a file with the given `path`.
    ///
    /// # Returns
    /// - `Ok(Some(content))`: The file content as a vector of bytes if the file exists and is read
    ///   successfully.
    /// - `Ok(None)`: If the file is not found (`Error::FileNotFound`).
    /// - `Err(E)`: If any other I/O error occurs during file opening or reading.
    pub fn read_file(&self, path: &str) -> Result<Option<Vec<u8>>> {
        match self.open_file(path, &OPEN_EXISTING_FOR_READ_ONLY) {
            Ok(file) => file.read_all().map(Some),
            Err(Error::FileNotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Writes the entire buffer to a file at the given path with the specified open options.
    pub fn write_file(&self, path: &str, buffer: &[u8], options: &OpenOptions) -> Result<()> {
        let file = self.open_file(path, options)?;
        file.write_all_at(0, buffer)?;
        Ok(())
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
        if self.is_dirty.swap(false, Ordering::AcqRel) {
            // TODO: Change to `let commit = cfg_if! { ... };` once attributes
            // are allowed on expressions:
            // https://github.com/rust-lang/rust/issues/15701
            cfg_if! {
                if #[cfg(feature = "storage_support_stage_during_udc")] {
                    let commit_result = self.inner.stageChangesForCommitOnAbUpdateComplete();
                } else {
                    let commit_result = self.inner.commitChanges();
                }
            };

            match commit_result {
                Ok(_) => Ok(()),
                Err(e) => {
                    // CRITICAL: If the commit fails, the session is likely still dirty.
                    // We must restore the flag to true so a subsequent retry (or drop warning)
                    // works. We use Release to ensure the restoration is visible.
                    self.mark_dirty();
                    Err(e.into())
                }
            }
        } else {
            debug!("Session is clean, commit skipped.");
            Ok(())
        }
    }

    /// Marks the current session as dirty.
    pub(crate) fn mark_dirty(&self) {
        self.is_dirty.store(true, Ordering::Release);
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Warn if the session is still marked as dirty when dropped.
        if self.is_dirty.load(Ordering::Acquire) {
            warn!("storage session dropped with uncommitted changes");
        }
    }
}
