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

//! Traits representing crypto abstractions and device specific functionality
use crate::data_structures::AuthenticatedConnectionState;
use crate::error::Error;
use alloc::boxed::Box;
use authgraph_core::key::{CertChain, InstanceIdentifier};
use authgraph_core::traits::{EcDsa, Rng};
use authmgr_common::signed_connection_request::TransportID;

/// The cryptographic functionality that must be provided by an implementation of AuthMgr BE
pub struct CryptoTraitImpl {
    /// Implementation of ECDSA functionality
    pub ecdsa: Box<dyn EcDsa>,
    /// Implementation of secure random number generation
    pub rng: Box<dyn Rng>,
}

/// Trait defining device specific functionality
pub trait Device: Send {
    /// Return the transport ID of the AuthMgr BE
    fn get_self_transport_id(&self) -> Result<TransportID, Error>;

    /// Secure storage invariant: we cannot allow a non-persistent pVM connect to secure storage
    /// without the secure storage knowing that it is a non-persistent client. Therefore, the
    /// AuthMgr BE should know whether a given pVM is persistent. In the first version of the
    /// trusted HAL project, we only support persistent pVM clients, therefore, in the first
    /// version, this could simply return true. When non-persistent pVMs are supported, it is
    /// expected that the AuthMgr BE learns via some out-of-band mechanism the instance ids of the
    /// peristence pVMs on the device.
    fn is_persistent_instance(&self, instance_id: &InstanceIdentifier) -> Result<bool, Error>;

    /// Connect to the trusted service identified by `service_name` and hand over the client
    /// connection along with the client's unique sequence number.
    fn handover_client_connection(
        &self,
        service_name: &str,
        client_seq_number: i32,
        client_conn_handle: Box<dyn RawConnection>,
        is_persistent: bool,
    ) -> Result<(), Error>;

    /// Check whether the persistent instance with the given instance id and the dice cert chain is
    /// allowed to be created.
    fn is_persistent_instance_creation_allowed(
        &self,
        instance_id: &InstanceIdentifier,
        dice_chain: &CertChain,
    ) -> Result<bool, Error>;

    /// Check whether a particular service requires to be notified upon deletion of a client.
    fn needs_notification_upon_client_deletion(&self, service_name: &str) -> Result<bool, Error>;
}

/// Trait defining RPC connection specific functionality required by AuthMgr BE
pub trait RpcConnection: Send {
    /// Return the transport ID of the instance that is on the other end of the connection
    fn get_peer_transport_id(&self) -> Result<TransportID, Error>;

    /// Store the re-usable information about the pvm and its clients in the connection state, to be
    /// used for serving multiple client authorization requests from an already authenticated pvm
    fn store_authenticated_state(
        &mut self,
        connection_state: AuthenticatedConnectionState,
    ) -> Result<(), Error>;

    /// Return the state if the state has been stored for this connecction. Since the state is
    /// stored only after the peer on the other side of the connection is authenticated, the
    /// existence of a connection state is also an indication that the connection is authenticated.
    fn get_authenticated_state(&self) -> Result<Option<&AuthenticatedConnectionState>, Error>;

    /// Return the mutable state if the state has been stored for this connection. Since the state
    /// is stored only after the peer on the other side of the connection is authenticated, the
    /// existence of a connection state is also an indication that the connection is authenticated.
    fn get_mutable_authenticated_state(
        &mut self,
    ) -> Result<Option<&mut AuthenticatedConnectionState>, Error>;

    /// Delete the state stored associated with the connection. This is called when the connection
    /// is closed.
    fn remove_authenticated_state(&mut self) -> Result<(), Error>;
}

/// Trait defining the raw connection specific functionality required by AuthMgr BE.
/// This is the out-of-band connection setup between the AuthMgr FE and AuthMgr BE, to be handedover
/// for the communication between a client in the pvm and the trusted service in TEE.
/// The handingover of the connection from the AuthMgr BE to the trusted service happens once the
/// client is authorized. AuthMgr BE invokes the `handover_client_connection` method of the `Device`
/// trait by passing an object of this trait implementation. Once the connection - which usually is
/// represented by a file descriptor - is handed over to the trusted service, the AuthMgr BE vendor
/// code should make sure that its handle to the underlying file descriptor is closed, but the
/// underlying file description is still open for the client and the trusted service to be able to
/// continue communication.
pub trait RawConnection: Send {
    /// Return the transport ID of the instance that is on the other end of the connection
    fn get_peer_transport_id(&self) -> Result<TransportID, Error>;

    /// Close the handle to this connection, while keeping the underlying connection is still open.
    /// At the end of `handover_client_connection`, the AuthMgrBE calls this method to remind the
    /// vendor code to close its handle to the file descriptor underlying this connection s.t.:
    /// 1) if the `handover_client_connection` is successful, the underlying file description
    ///    should be kept open for the client and the trusted service to be able to communicate.
    /// 2) if the `handover_client_connection` failed, then this is the last handle to the file
    ///    description underlying this connection from the AuthMgr BE side, and therefore, closing
    ///    the handle to it should close the underlying file description.
    ///
    ///  If the aforementioned behavior is already taken care of in the implementation of
    /// `handover_client_connection` trait method, this method can simply return Ok(()).
    fn close_handle(&mut self) -> Result<(), Error>;

    /// Return the raw file descriptor id of the underlying connection. This method is not called by
    /// the authmgr backend core library. Rather, this is added for use of the vendor
    /// implementations of `handover_client_connection` which is passed in an implementation of
    /// this `RawConnection` trait.
    ///
    /// Note that as per the Rust I/O safety guidelines:
    /// (https://doc.rust-lang.org/stable/std/io/index.html#io-safety) it is unsound to take an
    /// integer and treat it as a file descriptor. We refrain from using an `OwnedFd` here to
    /// preserve the no_std property of this crate. Therefore, the implementations should make sure
    /// that an object of this trait owns the file descriptor underlying the connection.
    fn get_raw_fd_id(&self) -> i32;
}
