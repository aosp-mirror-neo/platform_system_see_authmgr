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

//! Implementation of the structures defined in hardware/interfaces/security/see/authmgr/aidl/
//! android/hardware/security/see/authmgr/SignedConnectionRequest.cddl

use crate::{amc_err, Error, ErrorCode, Result};
use alloc::vec::Vec;
use authgraph_core::key::{EcSignKey, EcVerifyKey};
use authgraph_core::traits::EcDsa;
use coset::iana::Algorithm;
use coset::{
    cbor::Value, AsCborValue, CborSerializable, CoseError, CoseSign1, CoseSign1Builder,
    HeaderBuilder, Result as CoseResult, TaggedCborSerializable,
};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

// According to the SignedConnectionRequest.cddl;
const CBOR_CONNECTION_REQUEST_ARRAY_LEN: usize = 3;

// According to the SignedConnectionRequest.cddl;
const CBOR_FFA_TRANSPORT_ID_ARRAY_LEN: usize = 2;

// Tag for the CBOR type buuid = #6.37(bstr .size 16) - see RFC8610 - Section 3.6
const BUUID_TAG: u64 = 37;

/// The unique id assigned to the `ConnectionRequest` payload structure
pub const CONNECTION_REQUEST_UUID: [u8; 16] = [
    0x34, 0xc8, 0x29, 0x16, 0x95, 0x79, 0x4d, 0x86, 0xba, 0xef, 0x59, 0x2a, 0x06, 0x64, 0x19, 0xe4,
];

/// Type alias for a cryptographic random of 32 bytes
pub type Challenge = [u8; 32];

/// Type alias for transport id (a.k.a. VM ID)
pub type TransportID = u16;

/// This is a temporary measure to use a hardcoded transport id for AuthMgr BE.
/// TODO: b/392905377
pub const TEMP_AUTHMGR_BE_TRANSPORT_ID: u16 = u16::from_le_bytes([0x24, 0x12]);
/// This is a temporary measure to use a hardcoded transport id for AuthMgr FE.
/// TODO: b/392905377
pub const TEMP_AUTHMGR_FE_TRANSPORT_ID: u16 = u16::from_le_bytes([0x06, 0x12]);

/// External AAD to be added to any Sig_structure signed by the DICE signing key, with the mandatory
/// field of `uuid_of_payload_struct` of type UUID v4 (RFC 9562). This field is required to ensure
/// that both the signer and the verifier refer to the same payload structure, given that there are
/// various payload structures signed by the DICE signing key in different protocols in Android.
pub struct ExternalAADForDICESigned {
    uuid_of_payload_struct: [u8; 16],
}

impl AsCborValue for ExternalAADForDICESigned {
    fn from_cbor_value(value: Value) -> CoseResult<Self> {
        if let Value::Bytes(uuid) = value {
            return Ok(Self {
                uuid_of_payload_struct: uuid.as_slice().try_into().map_err(|_e| {
                    CoseError::UnexpectedItem("an invalid vector of bytes", "A valid UUID [u8; 16]")
                })?,
            });
        }
        Err(CoseError::UnexpectedItem("a vector of 16 bytes", "Cbor value of non-bytes"))
    }

    fn to_cbor_value(self) -> CoseResult<Value> {
        Ok(Value::Bytes(self.uuid_of_payload_struct.to_vec()))
    }
}

impl CborSerializable for ExternalAADForDICESigned {}

impl TaggedCborSerializable for ExternalAADForDICESigned {
    const TAG: u64 = BUUID_TAG;
}

/// An integer that identifies the type of the transport used for communication between clients and
/// trusted services
#[repr(u8)]
#[derive(Clone, Debug, FromPrimitive, PartialEq)]
pub enum TransportType {
    /// FFA transport
    FFA = 1,
}

/// Identity information of the peers provided by the transport layer
#[derive(Clone, Debug, PartialEq)]
pub enum TransportIdInfo {
    /// FFA transport identity information of the peers
    FFATransportId {
        /// AuthMgr FE's transport ID (a.k.a VM ID)
        fe_id: TransportID,
        /// AuthMgr BE's transport ID (a.k.a VM ID)
        be_id: TransportID,
    },
}

/// The payload structure signed by the DICE signing key for authentication
#[derive(Clone, Debug, PartialEq)]
pub struct ConnectionRequest {
    challenge: Challenge,
    transport_type: TransportType,
    transport_id_info: TransportIdInfo,
}

impl AsCborValue for ConnectionRequest {
    fn from_cbor_value(value: Value) -> CoseResult<Self> {
        let mut connection_req_cbor_array = match value {
            Value::Array(a) if a.len() == CBOR_CONNECTION_REQUEST_ARRAY_LEN => a,
            _ => {
                return Err(CoseError::UnexpectedItem("_", "array with three items"));
            }
        };
        let transport_id_info_cbor_val = connection_req_cbor_array.remove(2);
        let transport_type = match connection_req_cbor_array.remove(1) {
            Value::Integer(ttype) => (TransportType::from_u8(ttype.try_into()?))
                .ok_or(CoseError::UnexpectedItem("_", "valid integer for transport id"))?,
            _ => {
                return Err(CoseError::UnexpectedItem("_", "Integer"));
            }
        };
        let transport_id_info = match transport_type {
            TransportType::FFA => {
                let mut transport_id_info_cbor_array = match transport_id_info_cbor_val {
                    Value::Array(a) if a.len() == CBOR_FFA_TRANSPORT_ID_ARRAY_LEN => a,
                    _ => {
                        return Err(CoseError::UnexpectedItem("_", "array with two items"));
                    }
                };
                let be_id: TransportID = match transport_id_info_cbor_array.remove(1) {
                    Value::Integer(i) => i.try_into()?,
                    _ => {
                        return Err(CoseError::UnexpectedItem("_", "Integer"));
                    }
                };
                let fe_id: TransportID = match transport_id_info_cbor_array.remove(0) {
                    Value::Integer(i) => i.try_into()?,
                    _ => {
                        return Err(CoseError::UnexpectedItem("_", "Integer"));
                    }
                };
                TransportIdInfo::FFATransportId { fe_id, be_id }
            }
        };

        let challenge: Challenge = match connection_req_cbor_array.remove(0) {
            Value::Bytes(c) => c.as_slice().try_into().map_err(|_e| {
                CoseError::UnexpectedItem("array of bytes with incorrect length", "[u8; 32]")
            })?,
            _ => {
                return Err(CoseError::UnexpectedItem(
                    "a cbor value that is not bytes",
                    "[u8; 32]",
                ));
            }
        };
        Ok(Self { challenge, transport_type, transport_id_info })
    }

    fn to_cbor_value(self) -> CoseResult<Value> {
        let mut array = Vec::<Value>::new();
        array
            .try_reserve(CBOR_CONNECTION_REQUEST_ARRAY_LEN)
            .map_err(|_| CoseError::EncodeFailed)?;
        array.push(Value::Bytes(self.challenge.to_vec()));
        array.push(Value::Integer((self.transport_type as u8).into()));
        match self.transport_id_info {
            TransportIdInfo::FFATransportId { fe_id, be_id } => {
                let mut arr = Vec::<Value>::new();
                arr.try_reserve(CBOR_FFA_TRANSPORT_ID_ARRAY_LEN)
                    .map_err(|_| CoseError::EncodeFailed)?;
                arr.push(Value::Integer(fe_id.into()));
                arr.push(Value::Integer(be_id.into()));
                array.push(Value::Array(arr))
            }
        }
        Ok(Value::Array(array))
    }
}

impl CborSerializable for ConnectionRequest {}

impl ConnectionRequest {
    /// Create a new connection request on top of FFA transport
    pub fn new_for_ffa_transport(
        challenge: Challenge,
        fe_id: TransportID,
        be_id: TransportID,
    ) -> Self {
        Self {
            challenge,
            transport_type: TransportType::FFA,
            transport_id_info: TransportIdInfo::FFATransportId { fe_id, be_id },
        }
    }

    /// Sign the given `ConnectionRequest`. We use the EcDsa trait from the authgraph traits.
    /// Note: for now, we expect the EcSignKey to be passed into this method, but for the
    /// environments where the private signing key cannot be passed directly, we need to introduce
    /// something similar to the `sign_data` trait method in the authgraph `Device` trait.
    pub fn sign(
        self,
        signing_key: &EcSignKey,
        ecdsa: &dyn EcDsa,
        cose_sign_algorithm: Algorithm,
    ) -> Result<Vec<u8>> {
        let conn_req_encoded = self.to_vec()?;
        let aad_encoded =
            ExternalAADForDICESigned { uuid_of_payload_struct: CONNECTION_REQUEST_UUID }
                .to_vec()?;
        let protected = HeaderBuilder::new().algorithm(cose_sign_algorithm).build();
        let cose_sign1 = CoseSign1Builder::new()
            .protected(protected)
            .try_create_detached_signature(&conn_req_encoded, &aad_encoded, |data| {
                ecdsa.sign(signing_key, data)
            })
            .map_err(|e| amc_err!(SigningFailed, "failed to sign data: {:?}", e))?
            .build();
        Ok(cose_sign1.to_vec()?)
    }

    /// Verify a signature on the given `ConnectionRequest`.
    pub fn verify(
        self,
        signature: &[u8],
        verify_key: &EcVerifyKey,
        ecdsa: &dyn EcDsa,
    ) -> Result<()> {
        let cose_sign1 = CoseSign1::from_slice(signature)?;
        let conn_req_encoded = self.to_vec()?;
        let aad_encoded =
            ExternalAADForDICESigned { uuid_of_payload_struct: CONNECTION_REQUEST_UUID }
                .to_vec()?;
        verify_key.validate_cose_key_params().map_err(|e| {
            amc_err!(SignatureVerificationFailed, "failed to validate verification key: {:?}", e)
        })?;
        cose_sign1
            .verify_detached_signature(&conn_req_encoded, &aad_encoded, |signature, data| {
                ecdsa.verify_signature(verify_key, data, signature)
            })
            .map_err(|e| {
                amc_err!(SignatureVerificationFailed, "failed to verify signature: {:?}", e)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authgraph_boringssl::ec::BoringEcDsa;
    use authgraph_boringssl::BoringRng;
    use authgraph_core::key::CertChain;
    use authgraph_core::traits::Rng;
    use authgraph_core_test::create_dice_cert_chain_for_guest_os;

    #[test]
    fn test_cbor_enc_dec_connection_request() {
        let conn_req = ConnectionRequest {
            challenge: [1; 32],
            transport_type: TransportType::FFA,
            transport_id_info: TransportIdInfo::FFATransportId { fe_id: 16, be_id: 30 },
        };
        let encoded_conn_req = conn_req.clone().to_vec().expect("cbor encoding failed.");
        let decoded_conn_req =
            ConnectionRequest::from_slice(&encoded_conn_req).expect("cbor decoding failed.");
        assert_eq!(conn_req, decoded_conn_req);
    }
    #[test]
    fn test_sign_verify_connection_request() {
        // Create a cert chain with a private key
        let (sign_key, _, cert_chain_bytes) = create_dice_cert_chain_for_guest_os(None, 1);
        // Retrieve the public signing key from the cert chain
        let cert_chain =
            CertChain::from_slice(&cert_chain_bytes).expect("failed to decode the dice chain");
        let ecdsa = BoringEcDsa;
        let verify_key = cert_chain.validate(&ecdsa).expect("failed to validate the cert chain");
        let signing_algorithm = verify_key.get_cose_sign_algorithm();
        // Sign the connection request
        let rng = BoringRng;
        let mut challenge = [0u8; 32];
        rng.fill_bytes(&mut challenge);
        let fe_id = u16::from_le_bytes([0x34, 0x12]);
        let be_id = u16::from_le_bytes([0x24, 0x13]);
        let conn_req = ConnectionRequest {
            challenge,
            transport_type: TransportType::FFA,
            transport_id_info: TransportIdInfo::FFATransportId { fe_id, be_id },
        };
        let signature = conn_req
            .clone()
            .sign(&sign_key, &ecdsa, signing_algorithm)
            .expect("failure in signing");
        // Verify
        assert!(conn_req.verify(&signature, &verify_key, &ecdsa).is_ok());
        // Try to verify signature against a different connection request and expect failure
        let mut challenge_d = [0u8; 32];
        rng.fill_bytes(&mut challenge_d);
        let conn_req_d = ConnectionRequest {
            challenge: challenge_d,
            transport_type: TransportType::FFA,
            transport_id_info: TransportIdInfo::FFATransportId { fe_id, be_id },
        };
        assert!(conn_req_d.verify(&signature, &verify_key, &ecdsa).is_err())
    }
}
