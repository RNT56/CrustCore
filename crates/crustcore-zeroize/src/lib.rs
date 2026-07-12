// SPDX-License-Identifier: Apache-2.0
//! Minimal volatile zeroization for the nano trust boundary.
//!
//! Nano may link only `crustcore*` crates, while secret buffers still need a
//! compiler-resistant wipe. The one `unsafe` operation is a byte-sized volatile
//! write into a live, exclusively borrowed allocation. It is isolated here so
//! every consumer can remain `#![forbid(unsafe_code)]` and the exception is easy
//! to audit.

#![deny(unsafe_op_in_unsafe_fn)]

use core::ops::{Deref, DerefMut};
use core::sync::atomic::{compiler_fence, Ordering};

/// An owned byte buffer overwritten with volatile zeroes before deallocation.
pub struct ZeroizingVec(Vec<u8>);

/// A fixed-size byte array overwritten with volatile zeroes on drop.
pub struct ZeroizingArray<const N: usize>([u8; N]);

impl<const N: usize> ZeroizingArray<N> {
    /// Wrap an owned byte array.
    #[must_use]
    pub fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Overwrite every byte and fence compiler reordering.
    pub fn zeroize(&mut self) {
        for byte in &mut self.0 {
            // SAFETY: identical to `ZeroizingVec::zeroize`: this is one live,
            // exclusively borrowed initialized byte in the backing array.
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

impl<const N: usize> Deref for ZeroizingArray<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> DerefMut for ZeroizingArray<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const N: usize> AsRef<[u8]> for ZeroizingArray<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> Drop for ZeroizingArray<N> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizingVec {
    /// Wrap an owned buffer.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Overwrite every initialized byte and fence compiler reordering.
    pub fn zeroize(&mut self) {
        for byte in &mut self.0 {
            // SAFETY: `byte` points to one initialized `u8` in an exclusively
            // borrowed live Vec allocation. A byte has no invalid bit patterns.
            // Volatile prevents removal as a dead store before deallocation.
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

impl Deref for ZeroizingVec {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ZeroizingVec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AsRef<[u8]> for ZeroizingVec {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl Drop for ZeroizingVec {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_zeroize_overwrites_every_byte() {
        let mut bytes = ZeroizingVec::new(vec![1, 2, 3, 4]);
        bytes.zeroize();
        assert_eq!(&*bytes, &[0, 0, 0, 0]);
    }

    #[test]
    fn fixed_array_zeroize_overwrites_every_byte() {
        let mut bytes = ZeroizingArray::new([7u8; 32]);
        bytes.zeroize();
        assert_eq!(&*bytes, &[0u8; 32]);
    }
}
