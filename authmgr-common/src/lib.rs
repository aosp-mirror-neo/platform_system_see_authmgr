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
use authgraph_core::key::{CertChain, DiceChainEntry, Policy};
use coset::{CborSerializable, CoseError};
use dice_policy::{DicePolicy, DICE_POLICY_VERSION};

pub mod signed_connection_request;

/// The command byte to indicate the intent to connect to the `IAuthMgrAuthorization` service via
/// RPC binder
pub const CMD_RPC: u8 = 0u8;
/// The command byte to indicate the intent to establish a raw connection
pub const CMD_RAW: u8 = 1u8;

/// Token length is 32 bytes
pub const TOKEN_LENGTH: usize = 32;
/// Type alias for a cryptographic random token (sent from AuthMgrFE to BE) of 32 bytes
pub type Token = [u8; TOKEN_LENGTH];

/// AuthMgr common error type
#[derive(Debug, PartialEq)]
pub struct Error(pub ErrorCode, pub String);

/// AuthMgr common error codes
#[derive(Debug, PartialEq)]
pub enum ErrorCode {
    /// CBOR encoding failed
    CborEncodingFailed,
    /// CBOR decoding failed
    CborDecodingFailed,
    /// Signing failed
    SigningFailed,
    /// Signature verification failed
    SignatureVerificationFailed,
    /// Failed to create a DICE policy
    DicePolicyCreationFailed,
    /// Failed to match DICE policy
    DicePolicyMatchingFailed,
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

/// Wrapper function around the dice_policy library API, to match a DICE chain with a DICE policy,
/// to be used in AuthMgr protocol.
pub fn match_dice_chain_with_policy(cert_chain: &CertChain, policy: &Policy) -> Result<bool> {
    let cert_chain = cert_chain.clone().to_vec()?;
    let result = dice_policy::chain_matches_policy(&cert_chain, &policy.0);
    Ok(result.is_ok())
}

/// Wrapper function around the dice_policy library API, to match a DICE certificate with a DICE
/// policy, to be used in AuthMgr protocol. A DICE policy created for a single DICE certificate is
/// expected to have up to only one nodeConstraintList, as per the DICE policy specification.
pub fn match_dice_cert_with_policy(dice_cert: &DiceChainEntry, policy: &Policy) -> Result<bool> {
    let dice_policy = DicePolicy::from_slice(&policy.0)?;
    if dice_policy.node_constraints_list.is_empty() {
        return Ok(true);
    }
    let dice_node = dice_cert
        .payload
        .full_map
        .as_ref()
        .ok_or(amc_err!(UnknownError, "no certificate payload found"))?;
    let result =
        dice_policy::check_constraints_on_node(&dice_policy.node_constraints_list[0], dice_node)
            .map_err(|_e| {
                amc_err!(DicePolicyMatchingFailed, "failed to match constraints on DICE cert")
            });
    Ok(result.is_ok())
}

/// Get a copy of this DICE policy extended with the given DICE policy. This is an AuthMgr
/// specific requirement where we create a DICE policy for a child DICE certificate and later
/// need to combine it with the policy for the parent DICE cert chain
pub fn extend_dice_policy_with(parent_policy: &Policy, child_policy: &Policy) -> Result<Policy> {
    let parent_policy = DicePolicy::from_slice(&parent_policy.0)?;
    let child_policy = DicePolicy::from_slice(&child_policy.0)?;
    // Match the version of the two policies
    if parent_policy.version != child_policy.version {
        return Err(amc_err!(DicePolicyCreationFailed, "policy versions do not match"));
    }
    let mut parent_node_constraints = parent_policy.node_constraints_list.to_vec();
    parent_node_constraints.extend_from_slice(&child_policy.node_constraints_list);
    let extended_policy = DicePolicy {
        version: DICE_POLICY_VERSION,
        node_constraints_list: parent_node_constraints.into_boxed_slice(),
    };
    Ok(Policy(extended_policy.to_vec()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::{vec, vec::Vec};
    use authgraph_boringssl::ec::BoringEcDsa;
    use authgraph_core::key::{
        AUTHORITY_HASH, CONFIG_DESC, GUEST_OS_COMPONENT_NAME, INSTANCE_HASH, MODE, SECURITY_VERSION,
    };
    use authgraph_core_test::{
        create_dice_cert_chain_for_guest_os, create_dice_leaf_cert, SAMPLE_INSTANCE_HASH,
    };
    use authmgr_common_util::{
        get_constraint_spec_for_static_trusty_ta, get_constraints_spec_for_trusty_vm,
        policy_for_dice_node,
    };
    use dice_policy_builder::{ConstraintSpec, ConstraintType, MissingAction, TargetEntry};

    #[test]
    fn test_dice_policy_extend() {
        // Create DICE chain 1 for a pvm instance
        let (_sign_key_1, cdi_values_1, cert_chain_bytes_1) =
            create_dice_cert_chain_for_guest_os(Some(SAMPLE_INSTANCE_HASH), 1);
        let cert_chain_1 =
            CertChain::from_slice(&cert_chain_bytes_1).expect("failed to decode cert_chain 1");
        // Create constraints spec 1
        let constraint_spec_1 = get_constraints_spec_for_trusty_vm();
        // Create policy 1 given constraints spec 1 and DICE chain 1
        let policy_1 = Policy(
            dice_policy_builder::policy_for_dice_chain(
                &cert_chain_bytes_1,
                constraint_spec_1.clone(),
            )
            .expect("failed to building policy 1")
            .to_vec()
            .expect("failed to encode policy 1"),
        );
        // Match DICE chain 1 to policy 1 and expect a match
        let result1 = match_dice_chain_with_policy(&cert_chain_1, &policy_1);
        assert!(result1.unwrap());
        // Create (child) DICE cert entry for DICE chain 1
        let leaf_cert_bytes_1 = create_dice_leaf_cert(cdi_values_1, "keymint", 1);
        let leaf_cert_1 =
            DiceChainEntry::from_slice(&leaf_cert_bytes_1).expect("failed to decode leaf cert 1");
        // Create a constraints spec for client 1
        let client_constraint_spec_km = get_constraint_spec_for_static_trusty_ta();
        // Create the client policy given the constraints spec and DICE cert entry
        let client_policy_1 = Policy(
            policy_for_dice_node(&leaf_cert_1, client_constraint_spec_km)
                .expect("failed to create dice policy for keymint")
                .to_vec()
                .expect("failed to encode policy for client TA 1"),
        );
        // Match the client's DICE cert entry and policy and expect a match
        let result_1a = match_dice_cert_with_policy(&leaf_cert_1, &client_policy_1);
        assert!(result_1a.unwrap());

        // Extend DICE chain 1 with leaf DICE cert 1
        let ecdsa = BoringEcDsa;
        let extended_dice_chain_1 =
            cert_chain_1.extend_with(&leaf_cert_1, &ecdsa).expect("failed to extend DICE chain 1");
        // Extend DICE policy 1 with client 1's DICE policy
        let extended_policy_1 = extend_dice_policy_with(&policy_1, &client_policy_1)
            .expect("failed to extend DICE policy 1");

        // Match the extended DICE chain 1 with the extended DICE policy 1 and expect a match
        let result1 = match_dice_chain_with_policy(&extended_dice_chain_1, &extended_policy_1);
        assert!(result1.unwrap());
    }

    // This test simulates the DICE chain to policy matching that takes place in the full AuthMgr
    // protocol, using:
    //     1) two different DICE chains representing two pvm instances,
    //     2) DICE policies for the two pvm instances,
    //     3) two individual DICE certificates (which are extension of the aforementioned two DICE
    //        chains) representing the client TAs in the aforementioned two pvm instances,
    //     4) DICE policies created for the client TAs.
    // We do the following checks:
    //     1) Matching of the DICE cert chain and the policy of a given pvm instance succeeds.
    //     2) Matching of the DICE cert chain of one pvm instance with the policy of the other pvm
    //        instance fails.
    //     3) DICE policies of the two instances do not pass the equality match
    //     4) Matching of the DICE certificate and the policy of a given client TA in a pvm instance
    //        succeeds
    //     5) Matching of the DICE certificate of one client TA and the policy of the other client
    //        TA fails.
    //     6) Matching of the extended DICE chain created for a client TA in a pvm and the extended
    //        DICE policy created for the same client TA succeeds.
    //     7) The extended DICE policies created for the two client TAs do not pass the equality
    //        check.
    //     8) Matching of the extended DICE chain created for one client and the extended DICE
    //        policy created for the other client fails.
    //     9) Rollback protection for pvm instance 1 with a new DICE chain created with a higher
    //        security version and an updated policy.
    #[test]
    fn simulate_authmgr_dice_verification() {
        // Create DICE chain 1 for a pvm instance
        let (_sign_key_1, cdi_values_1, cert_chain_bytes_1) =
            create_dice_cert_chain_for_guest_os(Some(SAMPLE_INSTANCE_HASH), 1);
        let cert_chain_1 =
            CertChain::from_slice(&cert_chain_bytes_1).expect("failed to decode cert_chain 1");
        // Create constraints spec 1
        let constraint_spec_1 = get_constraints_spec_for_trusty_vm();
        // Create policy 1 given constraints spec 1 and DICE chain 1
        let policy_1 = Policy(
            dice_policy_builder::policy_for_dice_chain(
                &cert_chain_bytes_1,
                constraint_spec_1.clone(),
            )
            .expect("failed to building policy 1")
            .to_vec()
            .expect("failed to encode policy 1"),
        );
        // Match DICE chain 1 to policy 1 and expect a match
        let result1 = match_dice_chain_with_policy(&cert_chain_1, &policy_1);
        assert_eq!(result1, Ok(true));

        // Create DICE chain 2 for a pvm instance (with different instance hash and security
        // version)
        let instance_hash: [u8; 64] = [
            0x1a, 0x3f, 0xc9, 0x6b, 0xe3, 0x95, 0x59, 0x40, 0x21, 0x09, 0x9d, 0xf3, 0xcd, 0xc7,
            0xa4, 0x2a, 0x7d, 0x7e, 0xf5, 0x8e, 0xe6, 0x4d, 0x84, 0x25, 0x1a, 0x51, 0x27, 0x9d,
            0x55, 0x8a, 0xe9, 0x90, 0xf5, 0x8e, 0xd6, 0x4d, 0x84, 0x25, 0x1a, 0x51, 0x86, 0x9d,
            0x5b, 0x3f, 0xc9, 0x6b, 0xe3, 0x95, 0x59, 0x40, 0x21, 0x09, 0x9d, 0xf3, 0xcd, 0xc7,
            0xa4, 0x2a, 0x7d, 0x7e, 0xf5, 0x8e, 0xf5, 0x3f,
        ];
        let (_sign_key_2, cdi_values_2, cert_chain_bytes_2) =
            create_dice_cert_chain_for_guest_os(Some(instance_hash), 2);
        let cert_chain_2 =
            CertChain::from_slice(&cert_chain_bytes_2).expect("failed to decode cert_chain 2");
        // Create (different) constraints spec 2
        let constraint_spec_2 = get_relaxed_constraints_spec_for_trusty_vm();
        // Create policy 2 given constraints spec 2 and DICE chain 2
        let policy_2 = Policy(
            dice_policy_builder::policy_for_dice_chain(&cert_chain_bytes_2, constraint_spec_2)
                .expect("failed to building policy 2")
                .to_vec()
                .expect("failed to encode policy 2"),
        );
        // Match DICE chain 2 with policy 2 and expect a match
        let result2 = match_dice_chain_with_policy(&cert_chain_2, &policy_2);
        assert_eq!(result2, Ok(true));

        // Compare policy 1 and policy 2 and expect a non-match
        assert_ne!(policy_1, policy_2);
        // Match DICE chain 1 with policy 2 and expect a non-match
        let result_12 = match_dice_chain_with_policy(&cert_chain_1, &policy_2);
        assert_eq!(result_12, Ok(false));
        // Match DICE chain 2 with policy 1 and expect a non-match
        let result_21 = match_dice_chain_with_policy(&cert_chain_2, &policy_1);
        assert_eq!(result_21, Ok(false));

        // Create (child) DICE cert entry for DICE chain 1
        let leaf_cert_bytes_1 = create_dice_leaf_cert(cdi_values_1, "keymint", 1);
        let leaf_cert_1 =
            DiceChainEntry::from_slice(&leaf_cert_bytes_1).expect("failed to decode leaf cert 1");
        // Create a constraints spec for client 1
        let client_constraint_spec_km = get_constraint_spec_for_static_trusty_ta();
        // Create the client policy given the constraints spec and DICE cert entry
        let client_policy_1 = Policy(
            policy_for_dice_node(&leaf_cert_1, client_constraint_spec_km)
                .expect("failed to create dice policy for keymint")
                .to_vec()
                .expect("failed to encode policy for client TA 1"),
        );
        // Match the client's DICE cert entry and policy and expect a match
        let result_1a = match_dice_cert_with_policy(&leaf_cert_1, &client_policy_1);
        assert_eq!(result_1a, Ok(true));

        // Create (child) DICE cert entry for DICE chain 2
        let leaf_cert_bytes_2 = create_dice_leaf_cert(cdi_values_2, "widevine", 1);
        let leaf_cert_2 =
            DiceChainEntry::from_slice(&leaf_cert_bytes_2).expect("failed to decode leaf cert 2");
        // Create constraints spec for client 2
        let client_constraint_spec_wv = get_constraint_spec_for_static_trusty_ta();
        // Create client policy giiven the constraints spec and DICE cert entry
        let client_policy_2 = Policy(
            policy_for_dice_node(&leaf_cert_2, client_constraint_spec_wv)
                .expect("failed to create dice policy for widevine")
                .to_vec()
                .expect("failed to encode policy for client TA 2"),
        );
        // Match the client's DICE cert entry and policy and expect a match
        let result_2a = match_dice_cert_with_policy(&leaf_cert_2, &client_policy_2);
        assert_eq!(result_2a, Ok(true));

        // Compare client 1's policy and client 2's policy and expect a non-match
        assert_ne!(client_policy_1, client_policy_2);
        // Match client 1's DICE cert entry with client 2's policy and expect a non-match
        let result_12 = match_dice_cert_with_policy(&leaf_cert_1, &client_policy_2);
        assert_eq!(result_12, Ok(false));
        // Match client 2's DICE cert entry with client 1's policy and expect a non-match
        let result_21 = match_dice_cert_with_policy(&leaf_cert_2, &client_policy_1);
        assert_eq!(result_21, Ok(false));

        // Extend DICE chain 1 with leaf DICE cert 1
        let ecdsa = BoringEcDsa;
        let extended_dice_chain_1 =
            cert_chain_1.extend_with(&leaf_cert_1, &ecdsa).expect("failed to extend DICE chain 1");
        // Extend DICE policy 1 with client 1's DICE policy
        let extended_dice_policy_1 = extend_dice_policy_with(&policy_1, &client_policy_1)
            .expect("failed to extend DICE policy 1");
        // Match the extended DICE chain 1 with the extended DICE policy 1 and expect a match
        let result1 = match_dice_chain_with_policy(&extended_dice_chain_1, &extended_dice_policy_1);
        assert_eq!(result1, Ok(true));

        // Extend DICE chain 2 with DICE cert entry 2
        let extended_dice_chain_2 =
            cert_chain_2.extend_with(&leaf_cert_2, &ecdsa).expect("failed to extend DICE chain 2");
        // Extend DICE policy 2 with client 2's DICE policy
        let extended_dice_policy_2 = extend_dice_policy_with(&policy_2, &client_policy_2)
            .expect("failed to extend DICE policy 2");
        // Match the extended DICE chain 2 with the extended DICE policy 2 and expect a match
        let result2 = match_dice_chain_with_policy(&extended_dice_chain_2, &extended_dice_policy_2);
        assert_eq!(result2, Ok(true));

        // Compare the extended policy 1 and the extended policy 2 and expect a non-match
        assert_ne!(extended_dice_policy_1, extended_dice_policy_2);
        // Match the extended DICE chain 1 with the extended policy 2 and expect a non-match
        let result12 =
            match_dice_chain_with_policy(&extended_dice_chain_1, &extended_dice_policy_2);
        assert_eq!(result12, Ok(false));
        // Match the extended DICE chain 2 with the extended policy 1 and expect a non-match
        let result21 =
            match_dice_chain_with_policy(&extended_dice_chain_2, &extended_dice_policy_1);
        assert_eq!(result21, Ok(false));

        // Test rollback protection via DICE policy:
        // Create a DICE chain 3 with the same instance hash as DICE chain 1, but with a higher
        // security version.
        let (_sign_key_3, _cdi_values_3, cert_chain_bytes_3) =
            create_dice_cert_chain_for_guest_os(Some(SAMPLE_INSTANCE_HASH), 3);
        let cert_chain_3 =
            CertChain::from_slice(&cert_chain_bytes_3).expect("failed to decode cert_chain 3");
        // Create policy 3 given constraint spec 1 and DICE chain 3
        let policy_3 = Policy(
            dice_policy_builder::policy_for_dice_chain(&cert_chain_bytes_3, constraint_spec_1)
                .expect("failed to building policy 3")
                .to_vec()
                .expect("failed to encode policy 3"),
        );
        // Match DICE chain 3 to policy 3 and expect a match
        let result3 = match_dice_chain_with_policy(&cert_chain_3, &policy_3);
        assert_eq!(result3, Ok(true));
        // Match DICE chain 3 to policy 1 and expect a match
        let result31 = match_dice_chain_with_policy(&cert_chain_3, &policy_1);
        assert_eq!(result31, Ok(true));
        // Match DICE chain 1 to policy 3 and expect a non-match
        let result13 = match_dice_chain_with_policy(&cert_chain_1, &policy_3);
        assert_eq!(result13, Ok(false));
    }

    // Returns a constraint spec as above, but without the security version check for
    // the node except the "vm_entry" node
    fn get_relaxed_constraints_spec_for_trusty_vm() -> Vec<ConstraintSpec> {
        vec![
            ConstraintSpec::new(
                ConstraintType::ExactMatch,
                vec![AUTHORITY_HASH],
                MissingAction::Fail,
                TargetEntry::All,
            ),
            ConstraintSpec::new(
                ConstraintType::ExactMatch,
                vec![MODE],
                MissingAction::Fail,
                TargetEntry::All,
            ),
            ConstraintSpec::new(
                ConstraintType::ExactMatch,
                vec![CONFIG_DESC, INSTANCE_HASH],
                MissingAction::Fail,
                TargetEntry::ByName(GUEST_OS_COMPONENT_NAME.to_string()),
            ),
            ConstraintSpec::new(
                ConstraintType::GreaterOrEqual,
                vec![CONFIG_DESC, SECURITY_VERSION],
                MissingAction::Fail,
                TargetEntry::ByName(GUEST_OS_COMPONENT_NAME.to_string()),
            ),
        ]
    }
}
