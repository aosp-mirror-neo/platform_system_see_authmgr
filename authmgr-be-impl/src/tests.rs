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

//! Unit tests for the AuthMgr BE core functionality using different trait implementations.
use crate::mock_storage::MockPersistentStorage;
use crate::AuthMgrBeDevice;
use authgraph_core::key::{CertChain, DiceChainEntry, InstanceIdentifier, Policy};
use authgraph_core_test::{
    create_dice_cert_chain_for_guest_os, create_dice_leaf_cert, CdiValues, SAMPLE_INSTANCE_HASH,
};
use authmgr_be::authorization::AuthMgrBE;
use authmgr_be::data_structures::MemoryLimits;
use authmgr_be_test::{test_auth_mgr_protocol_succeeds_single_pvm, Client, PVM};
use authmgr_common::signed_connection_request::TEMP_AUTHMGR_BE_TRANSPORT_ID;
use authmgr_common_util::{
    get_constraint_spec_for_static_trusty_ta, get_constraints_spec_for_trusty_vm,
    policy_for_dice_node,
};
use coset::CborSerializable;
use std::collections::HashMap;

const HWCRYPTO_SERVICE_NAME: &str = "hwcrypto";
const SECURE_STORAGE_SERVICE_NAME: &str = "secure_storage";

#[test]
fn test_auth_mgr_protocol_single_pvm() {
    // Create a single persistent pvm with two clients, with the corresponding entries in the
    // AuthMgrBeDevice
    let (sign_key, cdi_values, dice_cert) =
        create_dice_cert_chain_for_guest_os(Some(SAMPLE_INSTANCE_HASH), 1);
    let cert_chain = CertChain::from_slice(&dice_cert).expect("error in decoding the dice cert");
    let pvm_instance_id = cert_chain
        .extract_instance_identifier_in_guest_os_entry()
        .expect("error in extracting instance id")
        .unwrap();
    let constraint_spec = get_constraints_spec_for_trusty_vm();

    let dice_policy = Policy(
        dice_policy_builder::policy_for_dice_chain(&dice_cert, constraint_spec)
            .expect("failed to build DICE policy for pvm")
            .to_vec()
            .expect("failed to encode DICE policy for pvm"),
    );

    let transport_id = u16::from_le_bytes([0x08, 0x04]);
    let crypto_traits = crate::crypto_trait_impls();
    let mut pvm = PVM::new(
        cert_chain,
        dice_policy.clone(),
        sign_key,
        crypto_traits.ecdsa,
        crypto_traits.rng,
        transport_id,
    );

    let leaf_cert_bytes_km = create_dice_leaf_cert(
        CdiValues { cdi_attest: cdi_values.cdi_attest, cdi_seal: cdi_values.cdi_seal },
        "keymint",
        1,
    );
    let dice_leaf_km =
        DiceChainEntry::from_slice(&leaf_cert_bytes_km).expect("error in decoding leaf cert");
    let client_constraint_spec_km = get_constraint_spec_for_static_trusty_ta();
    let dice_leaf_policy_km = Policy(
        policy_for_dice_node(&dice_leaf_km, client_constraint_spec_km)
            .expect("failed to create dice policy for keymint")
            .to_vec()
            .expect("failed to encode policy for keymint TA"),
    );
    let km_ta = Client::new(
        dice_leaf_km,
        dice_leaf_policy_km,
        vec![HWCRYPTO_SERVICE_NAME.to_string(), SECURE_STORAGE_SERVICE_NAME.to_string()],
        crate::crypto_trait_impls().rng,
    );
    pvm.add_client(km_ta);

    let leaf_cert_bytes_wv = create_dice_leaf_cert(cdi_values, "widevine", 1);
    let dice_leaf_wv =
        DiceChainEntry::from_slice(&leaf_cert_bytes_wv).expect("error in decoding leaf cert");
    let client_constraint_spec_wv = get_constraint_spec_for_static_trusty_ta();
    let dice_leaf_policy_wv = Policy(
        policy_for_dice_node(&dice_leaf_wv, client_constraint_spec_wv)
            .expect("failed to create dice policy for widevine")
            .to_vec()
            .expect("failed to encode policy for widevine TA"),
    );
    let wv_ta = Client::new(
        dice_leaf_wv,
        dice_leaf_policy_wv,
        vec![HWCRYPTO_SERVICE_NAME.to_string(), SECURE_STORAGE_SERVICE_NAME.to_string()],
        crate::crypto_trait_impls().rng,
    );
    pvm.add_client(wv_ta);

    let mut allowed_persistent_instances = HashMap::<InstanceIdentifier, Policy>::new();
    allowed_persistent_instances.insert(pvm_instance_id.clone(), dice_policy);

    let device = AuthMgrBeDevice::new(TEMP_AUTHMGR_BE_TRANSPORT_ID, allowed_persistent_instances);

    let mut authmgr_be = AuthMgrBE::new(
        crate::crypto_trait_impls(),
        Box::new(device),
        Box::new(MockPersistentStorage::new()),
        MemoryLimits::default(),
    )
    .expect("error in creating AuthMgrBE.");

    test_auth_mgr_protocol_succeeds_single_pvm(&mut authmgr_be, pvm);
}
