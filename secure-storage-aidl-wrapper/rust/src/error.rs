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

//! Error handling for the storage wrapper module
use alloc::string::String;
use alloc::string::ToString;
use android_hardware_security_see_storage::aidl::android::hardware::security::see::storage::{
    ISecureStorage::{
        ERR_AB_UPDATE_IN_PROGRESS, ERR_ALREADY_EXISTS, ERR_BAD_TRANSACTION,
        ERR_FS_TAMPERED, ERR_NOT_FOUND, ERR_UNSUPPORTED_PROPERTIES,
    },
};
use android_hardware_security_see_storage::binder;
use core::num::TryFromIntError;
use thiserror::Error;

/// Error types for the storage wrapper
#[derive(Error, Debug)]
pub enum Error {
    /// The requested storage properties are not supported
    #[error("Unsupported properties")]
    UnsupportedProperties,

    /// File does not exist
    #[error("File not found: {0}")]
    FileNotFound(String),

    /// File already exists
    #[error("File already exists: {0}")]
    FileAlreadyExists(String),

    /// Errorneous Transaction
    #[error("Bad transaction")]
    BadTransaction,

    /// A/B update in progress
    #[error("A/B update in progress")]
    AbUpdateInProgress,

    /// File system is tampered
    #[error("FS tampered")]
    FsTampered,

    /// Binder error
    #[error("Binder transaction failed: {status}")]
    Binder {
        /// Returned status
        status: binder::Status,
    },

    /// Read mismatch error
    #[error("Read returned unexpected size: expected {expected}, got {actual}")]
    ReadSizeMismatch {
        /// Expected size
        expected: usize,
        /// Actual size
        actual: usize,
    },

    /// Write mismatch error
    #[error("Failed to write all bytes: expected {expected}, wrote {actual}")]
    WriteSizeMismatch {
        /// Expected size
        expected: usize,
        /// Actual size
        actual: usize,
    },

    /// Errors encountered when converting integer types in AIDL calls
    #[error(transparent)]
    IntConversion(#[from] TryFromIntError),

    /// Fallible allocation error
    #[error("Failed to allocate memory")]
    MemoryAllocationFailed(#[from] alloc::collections::TryReserveError),
}

/// `Result`` type for storage wrapper
pub type Result<T> = core::result::Result<T, Error>;

/// Converts a `binder::Status` from a file operation (like open or delete) into a `storage::Error`.
pub fn file_op_error_to_storage_error(status: binder::Status, path: &str) -> Error {
    match status.service_specific_error() {
        ERR_NOT_FOUND => Error::FileNotFound(path.to_string()),
        ERR_ALREADY_EXISTS => Error::FileAlreadyExists(path.to_string()),
        _ => status.into(),
    }
}

impl From<binder::Status> for Error {
    fn from(status: binder::Status) -> Self {
        match status.service_specific_error() {
            ERR_FS_TAMPERED => Error::FsTampered,
            ERR_UNSUPPORTED_PROPERTIES => Error::UnsupportedProperties,
            ERR_AB_UPDATE_IN_PROGRESS => Error::AbUpdateInProgress,
            ERR_BAD_TRANSACTION => Error::BadTransaction,
            _ => Error::Binder { status },
        }
    }
}

impl From<binder::StatusCode> for Error {
    fn from(status_code: binder::StatusCode) -> Self {
        binder::Status::from(status_code).into()
    }
}
