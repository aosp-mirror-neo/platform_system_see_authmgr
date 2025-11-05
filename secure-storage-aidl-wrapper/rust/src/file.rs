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

//! Module that implements a file for accessing the secure storage
use crate::error::{Error, Result};
use crate::session::Session;
use alloc::vec::Vec;
use android_hardware_security_see_storage::aidl::android::hardware::security::see::storage::{
    CreationMode::CreationMode, FileMode::FileMode, IFile::IFile, OpenOptions::OpenOptions,
};
use android_hardware_security_see_storage::binder::Strong;
use core::sync::atomic::Ordering;

/// Options for opening a file for writing and reading, creating it if needed.
pub const OPEN_READ_WRITE: OpenOptions = OpenOptions {
    createMode: CreationMode::CREATE,
    accessMode: FileMode::READ_WRITE,
    truncateOnOpen: false,
};

/// Options for opening a file for reading only.
pub const OPEN_EXISTING_FOR_READ_ONLY: OpenOptions = OpenOptions {
    createMode: CreationMode::NO_CREATE,
    accessMode: FileMode::READ_ONLY,
    truncateOnOpen: false,
};

/// Options for opening a new file for writing.
pub const OPEN_NEW_FOR_WRITE_ONLY: OpenOptions = OpenOptions {
    createMode: CreationMode::CREATE_EXCLUSIVE,
    accessMode: FileMode::WRITE_ONLY,
    truncateOnOpen: false,
};

/// Options for opening an existing file for overwriting the entire file.
pub const OPEN_EXISTING_FOR_OVERWRITE: OpenOptions = OpenOptions {
    createMode: CreationMode::NO_CREATE,
    accessMode: FileMode::WRITE_ONLY,
    truncateOnOpen: true,
};

/// A safe wrapper around the `IFile` AIDL interface.
///
/// A `File` holds an immutable reference to its parent `Session`, ensuring
/// that the session always outlives any file handles associated with it.
pub struct File<'a> {
    inner: Strong<dyn IFile>,
    session: &'a Session,
}

impl File<'_> {
    /// Constructor to be used when returning a file object when open_file is called on a storage
    /// session.
    pub(crate) fn new<'a>(file: Strong<dyn IFile>, session: &'a Session) -> File<'a> {
        File { inner: file, session }
    }

    /// Gets the size of the file in bytes.
    pub fn get_size(&self) -> Result<usize> {
        Ok(self.inner.getSize()?.try_into()?)
    }

    /// Checks if the file is empty.
    pub fn is_empty(&self) -> Result<bool> {
        self.get_size().map(|size| size == 0)
    }

    /// Sets the size of the file. This may truncate or expand the file.
    pub fn set_size(&self, new_size: usize) -> Result<()> {
        self.session.is_dirty.store(true, Ordering::Relaxed);
        self.inner.setSize(new_size.try_into()?)?;
        Ok(())
    }

    /// Reads the entire content of the file.
    pub fn read_all(&self) -> Result<Vec<u8>> {
        let size = self.get_size()?;
        self.read_all_at(0, size)
    }

    /// Reads exactly `size` bytes from the file starting at a specific `offset`.
    ///
    /// Returns an error if the number of bytes read does not match the requested size.
    pub fn read_all_at(&self, offset: usize, size: usize) -> Result<Vec<u8>> {
        let data = self.read_at(offset, size)?;
        if data.len() == size {
            Ok(data)
        } else {
            Err(Error::ReadSizeMismatch { expected: size, actual: data.len() })
        }
    }

    /// Reads `size` bytes from the file starting at a specific `offset`.
    ///
    /// Returns an error if the number of bytes read does not match the requested size.
    /// This will also return an error if `size` is larger than the storage service's maximum
    /// read (chunk) size.
    pub fn read_at(&self, offset: usize, size: usize) -> Result<Vec<u8>> {
        let data = self.inner.read(size.try_into()?, offset.try_into()?)?;
        if data.len() <= size {
            Ok(data)
        } else {
            Err(Error::ReadSizeMismatch { expected: size, actual: data.len() })
        }
    }

    /// Reads an array of `N` bytes from a specific offset.
    pub fn read_array_at<const N: usize>(&self, offset: usize) -> Result<[u8; N]> {
        let data_vec = self.read_all_at(offset, N)?;
        // TODO(b/451483572): Use slice_as_array to avoid redundant copy for the vector to array
        // conversion below.
        data_vec
            .try_into()
            .map_err(|vec: Vec<_>| Error::ReadSizeMismatch { expected: N, actual: vec.len() })
    }

    /// Writes a buffer to the file at a given `offset`.
    ///
    /// Returns the number of bytes written.
    pub fn write_at(&self, offset: usize, buffer: &[u8]) -> Result<usize> {
        self.session.is_dirty.store(true, Ordering::Relaxed);
        Ok(self.inner.write(offset.try_into()?, buffer)?.try_into()?)
    }

    /// Writes the entire buffer to the file at a given `offset`.
    ///
    /// This method ensures that all bytes from the buffer are written. It returns an
    /// error if the number of bytes written does not match the buffer's length.
    pub fn write_all_at(&self, offset: usize, buffer: &[u8]) -> Result<()> {
        self.session.is_dirty.store(true, Ordering::Relaxed);
        let size_written = self.write_at(offset, buffer)?;

        if size_written == buffer.len() {
            Ok(())
        } else {
            Err(Error::WriteSizeMismatch { expected: buffer.len(), actual: size_written })
        }
    }
}
