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

//! Traits required by concrete implementations of an AuthMgr Frontend (FE)

use crate::error::Error;
use authmgr_common::signed_connection_request::TransportIdInfo;

/// Device specific behavior that a concrete implementation needs to provide
pub trait Device: Send {
    /// This function can be implemented to provide a unique instance id for
    /// a given AuthMgr FE.
    ///
    /// For AuthMgr FEs running in pVMs this should return None because the
    /// DICE chain for the pVM should contain the instance identifier.
    fn get_out_of_band_identifier(&self) -> Option<[u8; 64]> {
        None
    }

    /// The transport info for the AuthMgr Frontend (this pVM) and the
    /// AuthMgr Backend (i.e. where IAuthMgrAuthorization is running)
    fn get_transport_id_info(&self) -> Result<TransportIdInfo, Error>;
}

/// Implementers of this trait are connections to the AuthMgr-BE requesting
/// to be handed over to a trusted service.
///
/// See `AuthMgrFe::authorize_connection` for more detail.
pub trait ConnectionToAuthorize {
    /// Send data on this connection. Implementers must send the entire buffer.
    fn send(&self, buff: &[u8]) -> Result<(), Error>;
}
