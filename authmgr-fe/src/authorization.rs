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

//! Core logic for an AuthMgr Frontend (FE) as defined in
//! hardware/interfaces/security/see/authmgr/IAuthMgrAuthorization.aidl

use crate::error::Error;
use crate::traits::Device;
use alloc::boxed::Box;
use alloc::vec::Vec;

use android_hardware_security_see_authmgr::aidl::android::hardware::security::see::authmgr::{
    DicePolicy::DicePolicy, ExplicitKeyDiceCertChain::ExplicitKeyDiceCertChain,
    IAuthMgrAuthorization::IAuthMgrAuthorization, SignedConnectionRequest::SignedConnectionRequest,
};
use android_hardware_security_see_authmgr::binder;
use authgraph_core::key::{CertChain, EcSignKey};
use authmgr_common::signed_connection_request::{Challenge, ConnectionRequest, TransportIdInfo};
use authmgr_common::CryptoTraitImpl;
use coset::CborSerializable;

/// The core logic for AuthMgr FE
pub struct AuthMgrFe {
    device: Box<dyn Device>,
    crypto: CryptoTraitImpl,
    authmgr: binder::Strong<dyn IAuthMgrAuthorization>,
    is_pvm_authenticated: bool,
}

impl AuthMgrFe {
    /// Create a new AuthMgrFE
    pub fn new(
        device: Box<dyn Device>,
        crypto: CryptoTraitImpl,
        authmgr: binder::Strong<dyn IAuthMgrAuthorization>,
    ) -> Self {
        AuthMgrFe { device, crypto, authmgr, is_pvm_authenticated: false }
    }

    /// Phase 1 authentication of the pvm
    ///
    /// `policy` is a CBOR-encoded DicePolicy as defined in
    /// hardware/interfaces/security/authgraph/aidl/android/hardware/security/authgraph/ \
    /// DicePolicy.cddl
    ///
    /// Callers should ensure that policies are specific to their pVMs and enforce rollback
    /// protection. At a minimum, this means enforcing that authority hashes match for all nodes in
    /// a chain and security versions are greater than or equal to the given policy. Callers may
    /// also want to ensure that the leaf component name matches in the case where multiple VMs are
    /// being signed with the same signing key. In this case, component names must be unique.
    ///
    /// It is strongly recommended to use the AOSP-provided `libdice_policy_builder` crate to create
    /// policies for a given dice chain.
    ///
    /// An Ok(()) Result indicates that the pVM has been successfully authenticated
    /// and can attempt to resolve authorized connections using phase 2 of the
    /// AuthMgr protocol.
    pub fn authenticate_pvm(
        &mut self,
        cert_chain: CertChain,
        signing_key: EcSignKey,
        policy: Vec<u8>,
    ) -> Result<(), Error> {
        let dice_chain = ExplicitKeyDiceCertChain { diceCertChain: cert_chain.to_vec()? };

        // We need to convert from Option<[u8: 64]> to what
        // initAuthentication expects, Option<&[u8]>
        let owned_oob_ident = self.device.get_out_of_band_identifier();
        let oob_ident = owned_oob_ident.as_ref().map(|i| i.as_slice());

        let challenge = self.authmgr.initAuthentication(&dice_chain, oob_ident)?;

        let signed_connection_request =
            self.get_signed_connection_request(challenge, signing_key)?;
        let dice_policy = DicePolicy { dicePolicy: policy };

        self.authmgr.completeAuthentication(&signed_connection_request, &dice_policy)?;

        // If we've reached this point, completeAuthentication returned Ok(()) and
        // we can consider this pVM successfully authenticated.
        self.is_pvm_authenticated = true;

        Ok(())
    }

    fn get_signed_connection_request(
        &self,
        challenge: Challenge,
        signing_key: EcSignKey,
    ) -> Result<SignedConnectionRequest, Error> {
        let transport_info = self.device.get_transport_id_info()?;
        let connection_request = match transport_info {
            TransportIdInfo::FFATransportId { fe_id, be_id } => {
                ConnectionRequest::new_for_ffa_transport(challenge, fe_id, be_id)
            }
        };
        let algo = signing_key.get_cose_sign_algorithm();

        let signed_buff =
            connection_request.sign(&signing_key, self.crypto.ecdsa.as_ref(), algo)?;

        Ok(SignedConnectionRequest { signedConnectionRequest: signed_buff })
    }
}
