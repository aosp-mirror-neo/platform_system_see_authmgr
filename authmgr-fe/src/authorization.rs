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
use crate::traits::{ConnectionToAuthorize, Device};
use alloc::boxed::Box;
use alloc::vec::Vec;

use android_hardware_security_see_authmgr::aidl::android::hardware::security::see::authmgr::{
    DiceChainEntry::DiceChainEntry, DiceLeafArtifacts::DiceLeafArtifacts, DicePolicy::DicePolicy,
    ExplicitKeyDiceCertChain::ExplicitKeyDiceCertChain,
    IAuthMgrAuthorization::IAuthMgrAuthorization, SignedConnectionRequest::SignedConnectionRequest,
};
use android_hardware_security_see_authmgr::binder;
use authgraph_core::key::{CertChain, DiceChainEntry as AuthGraphDiceChainEntry, EcSignKey};
use authmgr_common::signed_connection_request::{Challenge, ConnectionRequest, TransportIdInfo};
use authmgr_common::{CryptoTraitImpl, Token, CMD_RAW, TOKEN_LENGTH};
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

    /// Authenticate a protected virtual machine (pVM).
    ///
    /// In IAuthMgrAuthorization this is referred to as phase 1 of the AuthMgr protocol.
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

    /// Authorize a connection on behalf of a client.
    ///
    /// In IAuthMgrAuthorization this is referred to as phase 2 of the AuthMgr protocol.
    ///
    /// A successful Result from this function indicates that the caller can hand the given
    /// connection back to the specified client and that client can expect that the requested
    /// trusted service will be on the other end of the connection (i.e. AuthMgr-BE has also
    /// handed its end of the connection off).
    ///
    /// `client_id` must be unique within this OS and should be enforced by an entity with greater
    /// privilege than AuthMgr-FE if possible. As an example, the Trusty OS uses trusted applet
    /// UUIDs, which are provided to AuthMgr-FE by the kernel during IPC.
    ///
    /// `leaf_policy` is a CBOR-encoded DicePolicy as defined in
    /// hardware/interfaces/security/authgraph/aidl/android/hardware/security/authgraph/ \
    /// DicePolicy.cddl
    ///
    /// A `leaf_policy` should be specified in such a way as to uniquely identify a client and
    /// prevent other clients within this pVM from impersonating that client. In the initial Trusty
    /// pVMs, we use UUIDs as component names for DICE leaf certs, but environments with dynamic app
    /// loading or multiple signing entities will need to consider limits on authorities, security
    /// versions, and other OS-specific policies.
    pub fn authorize_connection(
        &self,
        connection: &dyn ConnectionToAuthorize,
        client_id: &[u8],
        service_name: &str,
        // TODO at the end of the day these values are just serialized directly.
        // It does not make sense for callers to serde only for us to ser again.
        dice_leaf: AuthGraphDiceChainEntry,
        leaf_policy: Vec<u8>,
    ) -> Result<(), Error> {
        // The initial message on the out of band connection consists of
        // a single byte control character (CMD_RAW) and a Token.
        let msg_size = 1 + TOKEN_LENGTH;
        let mut initial_msg = Vec::new();
        initial_msg.try_reserve(msg_size)?;
        initial_msg.push(CMD_RAW);
        initial_msg.resize(msg_size, 0);
        let token: &mut Token = &mut initial_msg[1..]
            .try_into()
            .expect("initial_msg should have TOKEN_LENGTH bytes remaining after initial CMD_RAW");
        self.crypto.rng.fill_bytes(token.as_mut_slice());

        connection.send(&initial_msg)?;

        let dice_leaf_artifacts = DiceLeafArtifacts {
            diceLeaf: DiceChainEntry { diceChainEntry: dice_leaf.to_vec()? },
            diceLeafPolicy: DicePolicy { dicePolicy: leaf_policy },
        };

        // We've established a connection to the AuthMgr-BE and sent a unique token over
        // to it. Now ask the AuthMgr-BE to authorize it.
        Ok(self.authmgr.authorizeAndConnectClientToTrustedService(
            client_id,
            service_name,
            token,
            &dice_leaf_artifacts,
        )?)
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
