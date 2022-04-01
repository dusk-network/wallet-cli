// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use core::cmp::Ordering;
use std::fmt;
use std::num::ParseFloatError;
use std::ops::{Add, Deref, Div, Mul, Sub};
use std::str::FromStr;

/// The underlying unit of Dusk
pub type Lux = u64;

const DUSK_UNIT: Lux = 1_000_000_000;
const DUSK_UNIT_F: f64 = DUSK_UNIT as f64;

pub(crate) const MIN: Dusk = Dusk(1);
pub(crate) const MAX: Dusk = Dusk(Lux::MAX);

/// Denomination for DUSK
#[derive(Copy, Clone, Eq)]
pub struct Dusk(Lux);

impl Dusk {
    /// Create Dusk from f64
    pub fn from(value: f64) -> Self {
        Self((value * DUSK_UNIT_F) as Lux)
    }

    /// Create Dusk from Lux
    pub fn from_lux(value: Lux) -> Self {
        Self(value)
    }

    /// Get value in Lux
    pub fn as_lux(&self) -> Lux {
        self.0
    }

    /// Get value as f64
    pub fn as_f64(&self) -> f64 {
        self.0 as f64 / DUSK_UNIT_F
    }

    /// Min between two values
    pub fn min(self, other: Self) -> Self {
        if self <= other {
            self
        } else {
            other
        }
    }
}

/// Core ops
/// Implementations of Addition, Subtraction, Multiplication,
/// Division, and Comparison operators for Dusk

/// Addition
impl Add for Dusk {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        Self(self.0 + other.0)
    }
}

/// Subtraction
impl Sub for Dusk {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        Self(self.0 - other.0)
    }
}

/// Multiplication
impl Mul for Dusk {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        Self((self.0 * other.0) / DUSK_UNIT)
    }
}

/// Division
impl Div for Dusk {
    type Output = Self;
    fn div(self, other: Self) -> Self {
        Self(((self.0 as f64 / other.0 as f64) * DUSK_UNIT_F) as Lux)
    }
}

/// Equality
impl PartialEq for Dusk {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl PartialEq<Lux> for Dusk {
    fn eq(&self, other: &Lux) -> bool {
        self.as_lux() == *other
    }
}
impl PartialEq<f64> for Dusk {
    fn eq(&self, other: &f64) -> bool {
        self.as_f64() == *other
    }
}

/// Comparison
impl PartialOrd for Dusk {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.0.partial_cmp(&other.0)
    }
}
impl PartialOrd<Lux> for Dusk {
    fn partial_cmp(&self, other: &Lux) -> Option<Ordering> {
        self.as_lux().partial_cmp(other)
    }
}
impl PartialOrd<f64> for Dusk {
    fn partial_cmp(&self, other: &f64) -> Option<Ordering> {
        self.as_f64().partial_cmp(other)
    }
}

/// Conversion ops
/// Conveninent conversion of primitives to and from Dusk

/// Floats are used directly as Dusk value
impl From<f64> for Dusk {
    fn from(val: f64) -> Self {
        Self::from(val)
    }
}

/// Lux represent Dusk in their underlying unit type
impl From<Lux> for Dusk {
    fn from(lux: Lux) -> Self {
        Self(lux)
    }
}

/// Strings are parsed as Dusk values (floats)
impl FromStr for Dusk {
    type Err = ParseFloatError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        f64::from_str(s).map(Dusk::from)
    }
}

/// Dusk derefs into its underlying Lux amount
impl Deref for Dusk {
    type Target = Lux;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Display
/// Let the user print stuff

impl fmt::Display for Dusk {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_f64())
    }
}

impl fmt::Debug for Dusk {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_f64())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basics() {
        let one = Dusk::from(1.0);
        let dec = Dusk::from(2.25);
        assert_eq!(one, DUSK_UNIT);
        assert_eq!(one, 1.0);
        assert_eq!(dec, 2.25);
    }

    #[test]
    fn compare_dusk() {
        let one = Dusk::from(1.0);
        let two = Dusk::from(2.0);
        let dec_a = Dusk::from(0.00025);
        let dec_b = Dusk::from(0.00190);
        assert!(one == one);
        assert!(one != two);
        assert!(one < two);
        assert!(one <= two);
        assert!(one >= one);
        assert!(dec_a < dec_b);
        assert!(one > dec_b);
    }

    #[test]
    fn ops_dusk_dusk() {
        let one = Dusk::from(1.0);
        let two = Dusk::from(2.0);
        let three = Dusk::from(3.0);
        assert_eq!(one + two, three);
        assert_eq!(three - two, one);
        assert_eq!(one * one, one);
        assert_eq!(two * one, two);
        assert_eq!(two / one, two);
        let point_five = Dusk::from(0.5);
        assert_eq!(one / two, point_five);
        assert_eq!(point_five * point_five, Dusk::from(0.25))
    }

    #[test]
    fn conversions() {
        let my_float = 35.049;
        let dusk: Dusk = my_float.into();
        assert_eq!(dusk, my_float);
        let one_dusk = 1_000_000_000u64;
        let dusk: Dusk = one_dusk.into();
        assert_eq!(dusk, 1.0);
        assert_eq!(*dusk, one_dusk);
        let dusk = Dusk::from_str("69.420").unwrap();
        assert_eq!(dusk, 69.420);
    }
}
