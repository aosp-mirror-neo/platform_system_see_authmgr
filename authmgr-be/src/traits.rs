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
use crate::data_structures::{ClientId, ConnectionAuthState, InstanceIdentifier};
use crate::error::Error;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use authgraph_core::key::CertChain;
use authmgr_common::signed_connection_request::TransportID;

/// Trait defining device specific functionality
pub trait Device: Send {
    /// Return the transport ID of the AuthMgr BE
    fn get_self_transport_id(&self) -> Result<TransportID, Error>;

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
        client_seq_number: i64,
        client_conn_handle: Box<dyn RawConnection>,
        is_persistent: bool,
    ) -> Result<(), Error>;

    /// Check whether the persistent instance with the given instance id and the dice cert chain is
    /// allowed to be created.
    fn is_persistent_instance_creation_allowed(
        &self,
        _instance_id: &InstanceIdentifier,
        _dice_chain: &CertChain,
    ) -> Result<bool, Error> {
        // The default implementation allows creation of persistent vms if TEE is in the factory
        // provisioning stage.
        self.is_factory_provisioning_allowed()
    }

    /// Return true if TEE  is in the factory provisioning stage.
    /// This information is useful to make two decisions in authmgr protocol:
    /// 1. whether to allow creation of persistent vms (persistent vms are allowed to be created by
    ///    default if the TEE is in the factory provisioning stage)
    /// 2. whether to skip deletion of certain test-vms that needs to survive reboot, at the boot
    ///    time of authmgr-be (all test-vms are deleted by default during reboot if the TEE is not
    ///    in the factory provisioning stage)
    fn is_factory_provisioning_allowed(&self) -> Result<bool, Error>;
}

/// Trait defining RPC connection specific functionality required by AuthMgr BE
pub trait RpcConnection: Send {
    /// Return the transport ID of the instance that is on the other end of the connection
    fn get_peer_transport_id(&self) -> Result<TransportID, Error>;

    /// Store the information about the current stage of the authentication life cycle of the
    /// connection.
    fn set_current_auth_state(&mut self, auth_state: ConnectionAuthState);

    /// Return the current stage of the authentication life cycle of the connection.
    fn current_auth_state(&self) -> Result<&ConnectionAuthState, Error>;

    /// Return a mutable version of the current stage of the authentication life cycle of the
    /// connection.
    fn current_mut_auth_state(&mut self) -> Result<&mut ConnectionAuthState, Error>;
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

/// The following traits define the storage related functionality for AuthMgr BE.
///
/// The AuthMgr BE needs to store three types of information:
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
///    storage of a client context is uniquely identified by the combination of the
///    instance identifier, instance sequence number and the client id - so that the storage
///    artifacts containing the client context can be queried during phase 2 of the protocol, given
///    the instance id, instance sequence number from phase 1 of the protocol and the client id
///    provided by the AuthMgr FE in phase 2.
///    TODO: b/443130600 - Optimization: Introduce the notion of a transaction and commit to the
///    Storage trait.
pub trait Storage: Send {
    /// Read data from given the file path. If the file path does not exist, return None.
    fn read(&self, file_path: &str) -> Result<Option<Vec<u8>>, Error>;

    /// Write the given data at the given file path.
    /// If WriteMode = OverwriteExisting, the intention is to update an existing file. It is
    /// important to make sure that all the existing data is discarded before writing the new data.
    /// If there is no existing file in the given path, return an error.
    /// If WriteMode = CreateExclusive, the intention is to create a new file. If a file already
    /// exists in the given file path, return an error.
    fn write(&mut self, file_path: &str, data: &[u8], write_mode: WriteMode) -> Result<(), Error>;

    /// Following helper methods (with default implementations) are added as part of the trait
    /// because the underlying storage may have restrictions w.r.t the characters used in the
    /// file paths.
    /// Following is how the file paths for the three types of files are constructed in the
    /// helper methods that follow:
    /// 1. The file that stores the global sequence number:
    ///    "GLOBAL_SEQ_NUM"
    /// 2. The file(s) that store the instance contexts:
    ///    instance_context_file_prefix + storage_path_separator + hex_encoded_instance_id
    /// 3. The file(s) that store the client contexts:
    ///    client_context_file_prefix + storage_path_separator + hex_encoded_instance_id +
    ///    instance_seq_num + storage_path_separator + hex_encoded_client_id
    ///
    /// Helper method with a default implementation to build the file path for an instance context.
    fn build_storage_file_path_for_instance(&self, instance_id: &InstanceIdentifier) -> String {
        let mut path = String::from(self.get_instance_context_storage_prefix());
        path.push_str(self.get_authmgr_be_storage_path_separator());
        path.push_str(&hex::encode(instance_id.0));
        path
    }

    /// Helper method with a default implementation to build the file path for a client context.
    fn build_storage_file_path_for_client(
        &self,
        instance_id: &InstanceIdentifier,
        vm_seq_num: i64,
        client_id: &ClientId,
    ) -> String {
        let mut path = String::from(self.get_client_context_storage_prefix());
        path.push_str(self.get_authmgr_be_storage_path_separator());
        path.push_str(&hex::encode(instance_id.0));
        path.push_str(self.get_authmgr_be_storage_path_separator());
        path.push_str(vm_seq_num.to_string().as_str());
        path.push_str(self.get_authmgr_be_storage_path_separator());
        path.push_str(&hex::encode(&client_id.0));
        path
    }

    /// Helper method to get the separator character used when constructing file paths.
    fn get_authmgr_be_storage_path_separator(&self) -> &'static str {
        const AUTHMGR_BE_STORAGE_SEPARATOR: &str = "-";
        AUTHMGR_BE_STORAGE_SEPARATOR
    }

    /// Helper method to get the file path for the storage location of the global sequence number.
    fn get_global_seq_num_storage_path(&self) -> &'static str {
        const GLOBAL_SEQ_NUM_STORAGE_PATH: &str = "GLOBAL_SEQ_NUM";
        GLOBAL_SEQ_NUM_STORAGE_PATH
    }

    /// Helper method to get the file path prefix for the storage of the instance contexts.
    fn get_instance_context_storage_prefix(&self) -> &'static str {
        const INSTANCE_CONTEXT_STORAGE_PREFIX: &str = "INSTANCE_CONTEXT";
        INSTANCE_CONTEXT_STORAGE_PREFIX
    }

    /// Helper method to get the file path prefix for the storage of the client contexts.
    fn get_client_context_storage_prefix(&self) -> &'static str {
        const CLIENT_CONTEXT_STORAGE_PREFIX: &str = "CLIENT_CONTEXT";
        CLIENT_CONTEXT_STORAGE_PREFIX
    }
}

/// An enum to express the storage write options.
pub enum WriteMode {
    /// Create the file and write to it, return an error if it already exists
    /// (i.e. overwrite = false)
    CreateExclusive,
    /// Overwrite an existing file, return an error if the file does not already exist
    /// (i.e. overwrite = true)
    OverwriteExisting,
}

/// We require the vendor to implement the Storage trait for both persistent and non-persistent
/// storage because this reduces the potential errors in the vendor code which otherwise would
/// have to handle a boolean passed to each trait method, indicating whether the method should
/// deal with the persistent or non persistent storage. We move that complexity to the generic
/// code by requiring the Storage trait to be implemented for the two types of storage.
/// TODO: b/399707150 - support non-persistent instances in the future.
/// Persistent Storage, inheriting the Storage trait.
pub trait PersistentStorage: Storage {}
