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
use crate::data_structures::{
    AuthenticatedConnectionState, ClientId, PersistentClientContext, PersistentInstanceContext,
};
use crate::error::Error;
use alloc::boxed::Box;
use alloc::sync::Arc;
use authgraph_core::key::{CertChain, InstanceIdentifier, Policy};
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
    /// persistence pVMs on the device.
    fn is_persistent_instance(&self, instance_id: &InstanceIdentifier) -> Result<bool, Error>;

    /// Connect to the trusted service identified by `service_name` and hand over the client
    /// connection along with the client's unique sequence number.
    /// The client connection is an object of the trait implementation: `RawConnection`. At the end
    /// of this method, the vendor implementation must close the handle to the file descriptor
    /// underlying this connection such that:
    /// 1) if the `handover_client_connection` is successful, the underlying file description
    ///    should be kept open for the client and the trusted service to be able to communicate.
    /// 2) if the `handover_client_connection` failed, then this is the last handle to the file
    ///    description underlying this connection from the AuthMgr BE side, and therefore, closing
    ///    the handle to it should close the underlying file description.
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

    /// Return the raw file descriptor id of the underlying connection. This method is not called by
    /// the authmgr backend core library. Rather, this is added for use of the vendor
    /// implementations of `handover_client_connection` which is passed in an implementation of
    /// this `RawConnection` trait.
    ///
    /// Note that as per the Rust I/O safety guidelines:
    /// (<https://doc.rust-lang.org/stable/std/io/index.html#io-safety>) it is unsound to take an
    /// integer and treat it as a file descriptor. We refrain from using an `OwnedFd` here to
    /// preserve the no_std property of this crate. Therefore, the implementations should make sure
    /// that an object of this trait owns the file descriptor underlying the connection.
    ///
    /// Also note that we transfer the ownership of the object into this function to make sure this
    /// method cannot be called twice on the same object. Therefore, the implementation of this
    /// method should make sure that the object's destructor doesn't get called at the end of this
    /// method, in order to make sure that the underlying connection stays alive for the client and
    /// the trusted service to communicate.
    fn into_raw_fd(self: Box<Self>) -> i32;
}

/// Following traits define the storage related functionality for AuthMgr BE. The AuthMgr BE
/// need to store three types of information:
/// 1) The latest global sequence number - this is used to assign a unique id for instances and
///    clients. Uniqueness is preserved across factory resets because this is stored in the
///    persistent storage. It is important to preserve the uniqueness across factory resets in order
///    to prevent "use-after-destroy" threats described in the AuthMgr threat model.
///
/// 2) Instance contexts - information related to an instance, such as the instance sequence number,
///    DICE policy, etc. The information contained in an instance context may vary depending on
///    whether the instance is persistent or not. The path to the storage of an instance context is
///    uniquely identified by the instance identifier - so that the storage artifact containing the
///    instance context can be queried during the authentication protocol, given the instance id -
///    which is usually extracted from the DICE chain of the instance.
///
/// 3) Client contexts - information related to a client in an instance, such as client sequence
///    number, DICE policy for the client's DICE certificate, etc. The information contained in a
///    client context may vary depending on whether the client is persistent or not. The path to the
///    storage of a client context is uniquely identified by the instance sequence number and the
///    client id - so that the storage artifact containing the client context can be queried during
///    phase 2 of the protocol, given the instance sequence number given by phase 1 of the
///    protocol and the client id provided by the AuthMgr FE in phase 2.
///
/// TODO: b/398286643
/// The storage trait will be simplified to have just two methods to read and write a file
/// as mentioned in the above bug, once the encoding and decoding is implemented for the relevant
/// structures.
/// We require the vendor to implement the Storage trait for both persistent and non-persistent
/// storage because this reduces the potential errors in the vendor code which otherwise would have
/// to handle a boolean passed to each trait method, indicating whether the method should deal with
/// the persistent or non persistent storage. We move that complexity to the generic code by having
/// the Storage trait implemented for the two types of storage.
pub trait Storage: Send {
    /// Instance context
    type InstanceContext;
    /// Client context
    type ClientContext;

    /// Use this method to update the instance's DICE policy in the secure storage.
    fn update_instance_policy_in_storage(
        &mut self,
        instance_id: &Arc<InstanceIdentifier>,
        latest_dice_policy: &Arc<Policy>,
    ) -> Result<(), Error>;

    /// Use this method to update the client's DICE policy.
    fn update_client_policy_in_storage(
        &mut self,
        instance_seq_number: i32,
        client_id: &Arc<ClientId>,
        latest_dice_policy: &Arc<Policy>,
    ) -> Result<(), Error>;

    /// Retrieve the information stored in the secure storage for the instance identified by the
    /// given instance identifier, if it exists in the AuthMgr BE's secure storage,
    /// otherwise, return None.
    fn read_instance_context(
        &self,
        instance_id: &Arc<InstanceIdentifier>,
    ) -> Result<Option<Self::InstanceContext>, Error>;

    /// Create the context for a particular pvm instance in the secure storage. The implementation
    /// of this method should make sure that there are no other instances created same instance id.
    /// This is important to enforce Trust On First Use (TOFU).
    fn create_instance_context(
        &mut self,
        instance_id: &Arc<InstanceIdentifier>,
        instance_info: Self::InstanceContext,
    ) -> Result<(), Error>;

    /// Retrieve the information stored in the secure storage for the client identified by the
    /// sequence number of the instance it belongs to and the client id, if it exists in the
    /// AuthMgr BE's secure storage, otherwise, return None.
    fn read_client_context(
        &self,
        instance_seq_number: i32,
        client_id: &Arc<ClientId>,
    ) -> Result<Option<Self::ClientContext>, Error>;

    /// Initialize the secure storage for a particular client. The implementation of this method
    /// should make sure that there are no clients created with the same client id for the given
    /// instance.
    fn create_client_context(
        &mut self,
        instance_seq_number: i32,
        client_id: &Arc<ClientId>,
        client_info: Self::ClientContext,
    ) -> Result<(), Error>;
}

/// Trait defining the persistent storage specific functionality.
/// (This is temporary, until b/398286643 is resolved)
pub trait PersistentStorage:
    Storage<InstanceContext = PersistentInstanceContext, ClientContext = PersistentClientContext>
{
    /// Retrieve the global sequence number stored in the factory-reset surviving secure storage of
    /// the AuthMgr BE. If it does not already exist, initialize it from 0.
    fn get_or_create_global_sequence_number(&mut self) -> Result<i32, Error>;

    /// Increment the global sequence number stored in the factory-reset surviving secure storage of
    /// the AuthMgr BE. Return the latest global sequence number if successful andan error if it
    /// does not exist in the AuthMgr BE's secure storage.
    fn increment_global_sequence_number(&mut self) -> Result<i32, Error>;
}
