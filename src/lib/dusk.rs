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

use rusk_abi::dusk;

/// The underlying unit of Dusk
pub type Lux = u64;

pub(crate) const MIN: Dusk = Dusk(dusk::LUX);
pub(crate) const MAX: Dusk = Dusk(dusk::dusk(f64::MAX));

/// Denomination for DUSK
#[derive(Copy, Clone, Eq)]
pub struct Dusk(Lux);

impl Dusk {
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
        let a = dusk::from_dusk(self.0);
        let b = dusk::from_dusk(other.0);
        Self(dusk::dusk(a * b))
    }
}

/// Division
impl Div for Dusk {
    type Output = Self;
    fn div(self, other: Self) -> Self {
        Self(dusk::dusk(self.0 as f64 / other.0 as f64))
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
        self.0 == *other
    }
}
impl PartialEq<f64> for Dusk {
    fn eq(&self, other: &f64) -> bool {
        self.0 == dusk::dusk(*other)
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
        self.0.partial_cmp(other)
    }
}
impl PartialOrd<f64> for Dusk {
    fn partial_cmp(&self, other: &f64) -> Option<Ordering> {
        self.0.partial_cmp(&dusk::dusk(*other))
    }
}

/// Conversion ops
/// Conveninent conversion of primitives to and from Dusk

/// Floats are used directly as Dusk value
impl From<f64> for Dusk {
    fn from(val: f64) -> Self {
        Self(dusk::dusk(val))
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

#[allow(clippy::from_over_into)]
impl Into<f64> for Dusk {
    fn into(self) -> f64 {
        dusk::from_dusk(self.0)
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
        let v: f64 = (*self).into();
        write!(f, "{}", v)
    }
}

impl fmt::Debug for Dusk {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let v: f64 = (*self).into();
        write!(f, "{}", v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basics() {
        let one = Dusk::from(1.0);
        let dec = Dusk::from(2.25);
        assert_eq!(one, 1.0);
        assert_eq!(dec, 2.25);
        assert_eq!(MIN, dusk::LUX);
        assert_eq!(MIN, Dusk::from(dusk::LUX));
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