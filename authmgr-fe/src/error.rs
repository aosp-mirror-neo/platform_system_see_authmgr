// Copyright 2024 Google LLC
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

//! Error definitions for AuthMgr FE

use alloc::collections::TryReserveError;
use android_hardware_security_see_authmgr::binder;
use authgraph_core::error::Error as AuthGraphError;
use coset::CoseError;

/// All errors thrown by AuthMgr FE
#[derive(Debug)]
pub enum Error {
    /// Errors thrown by the IAuthMgrAuthorization service
    BinderStatus(binder::Status),
    /// Errors from the authmgr_common lib
    AuthMgrCommonError(authmgr_common::Error),
    /// Errors working with COSE objects
    CoseError(coset::CoseError),
    /// An error with a provided crypto operation
    CryptoError(AuthGraphError),
    /// A fallible allocation has failed
    FailedAlloc,
    /// Failed to connect to AuthMgr-BE
    AuthMgrBeConnectionFailed,
}

impl From<binder::Status> for Error {
    fn from(s: binder::Status) -> Self {
        Self::BinderStatus(s)
    }
}

impl From<binder::StatusCode> for Error {
    fn from(s: binder::StatusCode) -> Self {
        Self::BinderStatus(s.into())
    }
}

impl From<coset::CoseError> for Error {
    fn from(e: CoseError) -> Self {
        Self::CoseError(e)
    }
}

impl From<AuthGraphError> for Error {
    fn from(e: AuthGraphError) -> Self {
        Self::CryptoError(e)
    }
}

impl From<authmgr_common::Error> for Error {
    fn from(e: authmgr_common::Error) -> Self {
        Self::AuthMgrCommonError(e)
    }
}

impl From<TryReserveError> for Error {
    fn from(_: TryReserveError) -> Self {
        Self::FailedAlloc
    }
}
