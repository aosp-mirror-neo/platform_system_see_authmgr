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

//! This is a re-usable implementation of the storage trait of AuthMgr-BE using
//! the AIDL interface of the secure storage.
#![no_std]
extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use authmgr_be::{
    am_err,
    error::{Error, ErrorCode},
    traits::{PersistentStorage, Storage, WriteMode},
};
use secure_storage_aidl_wrapper::{
    error::Error as StorageError,
    file::{
        File, OPEN_EXISTING_FOR_OVERWRITE, OPEN_EXISTING_FOR_READ_ONLY, OPEN_NEW_FOR_WRITE_ONLY,
    },
    session::{Session, TAMPER_PROOF_EARLY_ACCESS_PERSISTENT_FS},
    OpenOptions, Strong,
};
pub use secure_storage_aidl_wrapper::{
    session::DEFAULT_SECURE_STORAGE_SERVICE_NAME, ISecureStorage,
};

/// Encapsulates a session established with the secure storage that is
/// accessed via the AIDL interface
pub struct SecureStorage {
    session: Session,
}

impl SecureStorage {
    /// Construct a `SecureStorage`, given a binder object for ISecureStorage, which contains
    /// a session to the securee storage. The binder object is passed into the constructor
    /// because obtaining the binder (RPC) object can be platform specific.
    pub fn new(storage_binder: &Strong<dyn ISecureStorage>) -> Result<Self, Error> {
        Ok(Self {
            session: Session::new(storage_binder, &TAMPER_PROOF_EARLY_ACCESS_PERSISTENT_FS)
                .map_err(|e| {
                    am_err!(InternalError, "error in creating a secure storage session: {:?}", e)
                })?,
        })
    }
}

impl Storage for SecureStorage {
    fn read(&self, file_path: &str) -> Result<Option<Vec<u8>>, Error> {
        match open_existing_file(&self.session, file_path, &OPEN_EXISTING_FOR_READ_ONLY)? {
            Some(file) => {
                let content = file
                    .read_all()
                    .map_err(|e| am_err!(InternalError, "error in reading the file: {:?}", e))?;
                Ok(Some(content))
            }
            None => Ok(None),
        }
    }

    fn write(&mut self, file_path: &str, data: &[u8], write_mode: WriteMode) -> Result<(), Error> {
        let file = match write_mode {
            WriteMode::CreateExclusive => open_new_file(&self.session, file_path)?,
            WriteMode::OverwriteExisting => {
                match open_existing_file(&self.session, file_path, &OPEN_EXISTING_FOR_OVERWRITE)? {
                    Some(file) => file,
                    None => {
                        return Err(am_err!(
                            InternalError,
                            "file does not exist in the given path: {:?}",
                            file_path
                        ))
                    }
                }
            }
        };
        file.write_all_at(0, data)
            .map_err(|e| am_err!(InternalError, "error in writing to the file: {:?}", e))?;
        self.session.commit().map_err(|e| am_err!(InternalError, "error in committing: {:?}", e))
    }

    fn list_file_names(&self) -> Result<Vec<String>, Error> {
        self.session
            .list_files_in_dir("")
            .map_err(|e| am_err!(InternalError, "error in listing the files: {:?}", e))
    }

    fn delete_file(&mut self, file_path: &str) -> Result<(), Error> {
        self.session.delete_file(file_path).map_err(|e| {
            am_err!(InternalError, "error {:?} in deleting file: {:?}", e, file_path)
        })?;
        self.session.commit().map_err(|e| am_err!(InternalError, "error in committing: {:?}", e))
    }
}

impl PersistentStorage for SecureStorage {}

fn open_existing_file<'a>(
    session: &'a Session,
    file_path: &'a str,
    open_options: &OpenOptions,
) -> Result<Option<File<'a>>, Error> {
    session.open_file(file_path, open_options).map_or_else(
        |e| {
            if let StorageError::FileNotFound(_) = e {
                Ok(None)
            } else {
                Err(am_err!(
                    InternalError,
                    "error in opening the file: {:?}, due to: {:?}",
                    file_path,
                    e
                ))
            }
        },
        |file| Ok(Some(file)),
    )
}

fn open_new_file<'a>(session: &'a Session, file_path: &str) -> Result<File<'a>, Error> {
    session.open_file(file_path, &OPEN_NEW_FOR_WRITE_ONLY).map_err(|e| {
        if let StorageError::FileAlreadyExists(s) = e {
            am_err!(InternalError, "file already exists in the given path: {:?}", s)
        } else {
            am_err!(InternalError, "error in opening the file: {:?}", e)
        }
    })
}
