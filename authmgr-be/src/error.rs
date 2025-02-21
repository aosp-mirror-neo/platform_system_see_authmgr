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

//! Error handling for AuthMgr Backend

use alloc::string::String;
use authgraph_core::error::Error as AGError;
use authmgr_common::{Error as AMError, ErrorCode as AMErrorCode};
use coset::CoseError;

/// AuthMgr BE error type
#[derive(Debug)]
pub struct Error(pub ErrorCode, pub String);

/// Internal error codes corresponding to values in `Error.aidl`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ErrorCode {
    /// Success
    Ok = 0,
    /// Duplicated attempt to start authentication from the same transport ID
    AuthenticationAlreadyStarted = -1,
    /// Duplicated authenticated attempt with the same instance ID
    InstanceAlreadyAuthenticated = -2,
    /// Invalid DICE certificate chain of the AuthMgr FE
    InvalidDiceCertChain = -3,
    /// Invalid DICE leaf of the client
    InvalidDiceLeaf = -4,
    /// Invalid DICE policy
    InvalidDicePolicy = -5,
    /// The DICE chain to policy matching failed
    DicePolicyMatchingFailed = -6,
    /// Invalid signature
    SignatureVerificationFailed = -7,
    /// Failed to handover the connection to the trusted service
    ConnectionHandoverFailed = -8,
    /// An authentication required request (e.g. phase 2) is invoked on a non-authenticated
    /// connection
    ConnectionNotAuthenticated = -9,
    /// There is no pending connection to authorize in phase 2
    NoConnectionToAuthorize = -10,
    /// Invalid instance identifier */
    InvalidInstanceIdentifier = -11,
    /// Failed to allocate memory
    MemoryAllocationFailed = -12,
    /// An instance which is pending deletion is trying to authenticate
    InstancePendingDeletion = -13,
    /// A client which is pending deletion is trying to authorize
    ClientPendingDeletion = -14,
    /// Trying to complete authentication for an instance for which authentication is not started
    AuthenticationNotStarted = -15,
    /// Creation of the pVM instance's context in the secure storage is not allowed
    InstanceContextCreationDenied = -16,
    /// A new connection for a client cannot be created from a non-authenticated pVM instance
    InstanceNotAuthenticated = -17,
    /// An authenticated connection between the AuthMgr FE and BE cannot be used as the connection
    /// between a client and a trusted service.
    NewConnectionRequiredForClient = -18,
    // Error codes corresponding to Binder error values
    /// Internal processing error
    InternalError = -19,
    /// Unimplemented
    Unimplemented = -20,
}

impl From<AGError> for Error {
    fn from(ag_error: AGError) -> Self {
        Error(ErrorCode::InternalError, ag_error.1)
    }
}

impl From<AMError> for Error {
    fn from(am_error: AMError) -> Self {
        match am_error.0 {
            AMErrorCode::SignatureVerificationFailed => {
                crate::am_err!(SignatureVerificationFailed, "{}", am_error.1)
            }
            AMErrorCode::DicePolicyMatchingFailed => {
                crate::am_err!(DicePolicyMatchingFailed, "{}", am_error.1)
            }
            _ => crate::am_err!(InternalError, "{}", am_error.1),
        }
    }
}

impl From<CoseError> for Error {
    fn from(e: CoseError) -> Self {
        crate::am_err!(InternalError, "COSE error: {:?}", e)
    }
}

impl From<::alloc::collections::TryReserveError> for Error {
    fn from(e: alloc::collections::TryReserveError) -> Self {
        crate::am_err!(MemoryAllocationFailed, "memory allocation failed: {:?}", e)
    }
}

/// Macro to build an [`Error`] instance.
/// E.g. use: `am_err!(InternalError, "some {} format", arg)`.
#[macro_export]
macro_rules! am_err {
    { $error_code:ident, $($arg:tt)+ } => {
        Error(ErrorCode::$error_code,
              alloc::format!("{}:{}: {}", file!(), line!(), format_args!($($arg)+))) };
        }
