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

//! Entry point to the AuthMgr-Common crate used by both AuthMgr-FE and AuthMgr-BE.

#![no_std]
extern crate alloc;

use alloc::string::String;
use coset::CoseError;

pub mod signed_connection_request;

/// AuthMgr common error type
#[derive(Debug)]
pub struct Error(pub ErrorCode, pub String);

/// AuthMgr common error codes
#[derive(Debug)]
pub enum ErrorCode {
    /// CBOR encoding failed
    CborEncodingFailed,
    /// CBOR decoding failed
    CborDecodingFailed,
    /// Signing failed
    SigningFailed,
    /// Signature verification failed
    SignatureVerificationFailed,
    /// Other error
    UnknownError,
}

/// AuthMgr common result type
pub type Result<T, E = Error> = core::result::Result<T, E>;

impl core::convert::From<CoseError> for Error {
    fn from(e: CoseError) -> Self {
        match e {
            CoseError::DecodeFailed(_) => amc_err!(CborDecodingFailed, "{}", e),
            CoseError::EncodeFailed => amc_err!(CborEncodingFailed, "{}", e),
            CoseError::UnexpectedItem(_, _) => amc_err!(CborDecodingFailed, "{}", e),
            _ => amc_err!(UnknownError, "{}", e),
        }
    }
}

/// Macro to build an [`Error`] instance.
/// E.g. use: `amc_err!(SigningFailed, "some {} format", arg)`.
#[macro_export]
macro_rules! amc_err {
    { $error_code:ident, $($arg:tt)+ } => {
        Error(ErrorCode::$error_code,
              alloc::format!("{}:{}: {}", file!(), line!(), format_args!($($arg)+))) };
}
