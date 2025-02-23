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

//! Entry point to the AuthMgr-Common-Util crate which provides helper methods.

extern crate alloc;

use alloc::vec::Vec;
use authgraph_core::key::{
    DiceChainEntry, AUTHORITY_HASH, COMPONENT_NAME, CONFIG_DESC, GUEST_OS_COMPONENT_NAME,
    INSTANCE_HASH, MODE, SECURITY_VERSION,
};
use authmgr_common::{amc_err, Error, ErrorCode, Result};
use dice_policy::{DicePolicy, NodeConstraints, DICE_POLICY_VERSION};
use dice_policy_builder::{
    constraints_on_dice_node, ConstraintSpec, ConstraintType, MissingAction, TargetEntry,
};

/// Construct a DICE policy for a given DICE node. This is a helper function around the
/// dice_policy_builder library to cater the AuthMgr specific requirement of building a DICE policy
/// for a client's DICE certificate.
pub fn policy_for_dice_node(
    dice_node: &DiceChainEntry,
    mut constraint_spec: Vec<ConstraintSpec>,
) -> Result<DicePolicy> {
    let mut constraints_list: Vec<NodeConstraints> = Vec::with_capacity(1);
    constraints_list.push(
        constraints_on_dice_node(
            dice_node
                .payload
                .full_map
                .as_ref()
                .ok_or(amc_err!(UnknownError, "DICE node payload not found"))?,
            &mut constraint_spec,
        )
        .map_err(|e| amc_err!(DicePolicyCreationFailed, "{}", e))?,
    );
    Ok(DicePolicy {
        version: DICE_POLICY_VERSION,
        node_constraints_list: constraints_list.into_boxed_slice(),
    })
}

/// Constraints spec to create a DICE policy for a DICE cert chain of a Trusty VM.
/// Note that this is a helper method only. The implementors of AuthMgr-FE should build a constraint
/// spec according to their environment and requirements.
pub fn get_constraints_spec_for_trusty_vm() -> Vec<ConstraintSpec> {
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
            ConstraintType::GreaterOrEqual,
            vec![CONFIG_DESC, SECURITY_VERSION],
            MissingAction::Ignore,
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

/// Constraints spec for a DICE certificate of a pvm client in Trusty.
/// Note that this is a helper method only. The implementors of AuthMgr-FE should build a constraint
/// spec according to the client configurations.
pub fn get_constraint_spec_for_static_trusty_ta() -> Vec<ConstraintSpec> {
    vec![ConstraintSpec::new(
        ConstraintType::ExactMatch,
        vec![CONFIG_DESC, COMPONENT_NAME],
        MissingAction::Fail,
        TargetEntry::All,
    )]
}
