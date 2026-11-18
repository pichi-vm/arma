// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Contiguous MMIO transport slots.

use core::ops::Range;

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct MmioSlots {
    base: u64,
    count: u32,
}

impl MmioSlots {
    pub(crate) const SIZE: u64 = 0x200;

    pub(crate) fn new(base: u64, count: u32) -> Option<Self> {
        base.checked_add(u64::from(count) * Self::SIZE)?;
        Some(Self { base, count })
    }

    pub(crate) fn iter(&self) -> impl ExactSizeIterator<Item = Range<u64>> {
        (0..self.count).map(move |index| {
            let start = self.base + u64::from(index) * Self::SIZE;
            start..start + Self::SIZE
        })
    }
}

#[cfg(test)]
mod tests {
    use super::MmioSlots;

    #[test]
    fn rejects_overflowing_extent() {
        let base = u64::MAX - MmioSlots::SIZE;
        assert_eq!(
            MmioSlots::new(base, 1).unwrap().iter().next(),
            Some(base..u64::MAX)
        );
        assert!(MmioSlots::new(base + 1, 1).is_none());
    }
}
