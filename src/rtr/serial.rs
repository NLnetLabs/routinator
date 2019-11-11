//! Serial numbers.
//!
//! This module define a type [`Serial`] that wraps a `u32` to provide
//! serial number arithmetics.
//!
//! [`Serial`]: struct.Serial.html

use std::{cmp, fmt, hash, str};


//------------ Serial --------------------------------------------------------

/// A serial number.
///
/// Serial numbers are regular integers with a special notion for comparison
/// in order to be able to deal with roll-over.
///
/// Specifically, addition and comparison are defined in [RFC 1982].
/// Addition, however, is only defined for values up to `2^31 - 1`, so we
/// decided to not implement the `Add` trait but rather have a dedicated
/// method `add` so as to not cause surprise panics.
/// 
/// Serial numbers only implement a partial ordering. That is, there are
/// pairs of values that are not equal but there still isn’t one value larger
/// than the other. Since this is neatly implemented by the `PartialOrd`
/// trait, the type implements that.
///
/// [RFC 1982]: https://tools.ietf.org/html/rfc1982
#[derive(Clone, Copy, Debug)]
pub struct Serial(pub u32);

impl Serial {
    pub fn from_be(value: u32) -> Self {
        Serial(u32::from_be(value))
    }

    pub fn to_be(self) -> u32 {
        self.0.to_be()
    }

    /// Add `other` to `self`.
    ///
    /// Serial numbers only allow values of up to `2^31 - 1` to be added to
    /// them. Therefore, this method requires `other` to be a `u32` instead
    /// of a `Serial` to indicate that you cannot simply add two serials
    /// together. This is also why we don’t implement the `Add` trait.
    ///
    /// # Panics
    ///
    /// This method panics if `other` is greater than `2^31 - 1`.
    #[allow(clippy::should_implement_trait)]
    pub fn add(self, other: u32) -> Self {
        assert!(other <= 0x7FFF_FFFF);
        Serial(self.0.wrapping_add(other))
    }
}


//--- From and FromStr

impl From<u32> for Serial {
    fn from(value: u32) -> Serial {
        Serial(value)
    }
}

impl From<Serial> for u32 {
    fn from(serial: Serial) -> u32 {
        serial.0
    }
}

impl str::FromStr for Serial {
    type Err = <u32 as str::FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        <u32 as str::FromStr>::from_str(s).map(Into::into)
    }
}


//--- Display

impl fmt::Display for Serial {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}


//--- PartialEq and Eq

impl PartialEq for Serial {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl PartialEq<u32> for Serial {
    fn eq(&self, other: &u32) -> bool {
        self.0.eq(other)
    }
}

impl Eq for Serial { }


//--- PartialOrd

impl cmp::PartialOrd for Serial {
    fn partial_cmp(&self, other: &Serial) -> Option<cmp::Ordering> {
        match self.0.cmp(&other.0) {
            cmp::Ordering::Equal => Some(cmp::Ordering::Equal),
            cmp::Ordering::Less => {
                let sub = other.0 - self.0;
                match sub.cmp(&0x8000_0000) {
                    cmp::Ordering::Less => Some(cmp::Ordering::Less),
                    cmp::Ordering::Greater => Some(cmp::Ordering::Greater),
                    _ => None
                }
            },
            cmp::Ordering::Greater => {
                let sub = self.0 - other.0;
                match sub.cmp(&0x8000_0000) {
                    cmp::Ordering::Less => Some(cmp::Ordering::Greater),
                    cmp::Ordering::Greater => Some(cmp::Ordering::Less),
                    _ => None
                }
            }
        }
    }
}


//--- Hash

impl hash::Hash for Serial {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}


//============ Testing =======================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn good_addition() {
        assert_eq!(Serial(0).add(4), Serial(4));
        assert_eq!(Serial(0xFF00_0000).add(0x0F00_0000),
                   Serial(((0xFF00_0000u64 + 0x0F00_0000u64)
                           % 0x1_0000_0000) as u32));
    }

    #[test]
    #[should_panic]
    fn bad_addition() {
        let _ = Serial(0).add(0x8000_0000);
    }

    #[test]
    fn comparison() {
        use std::cmp::Ordering::*;

        assert_eq!(Serial(12), Serial(12));
        assert_ne!(Serial(12), Serial(112));

        assert_eq!(Serial(12).partial_cmp(&Serial(12)), Some(Equal));

        // s1 is said to be less than s2 if [...]
        // (i1 < i2 and i2 - i1 < 2^(SERIAL_BITS - 1))
        assert_eq!(Serial(12).partial_cmp(&Serial(13)), Some(Less));
        assert_ne!(Serial(12).partial_cmp(&Serial(3_000_000_012)), Some(Less));

        // or (i1 > i2 and i1 - i2 > 2^(SERIAL_BITS - 1))
        assert_eq!(Serial(3_000_000_012).partial_cmp(&Serial(12)), Some(Less));
        assert_ne!(Serial(13).partial_cmp(&Serial(12)), Some(Less));

        // s1 is said to be greater than s2 if [...]
        // (i1 < i2 and i2 - i1 > 2^(SERIAL_BITS - 1))
        assert_eq!(Serial(12).partial_cmp(&Serial(3_000_000_012)),
                   Some(Greater));
        assert_ne!(Serial(12).partial_cmp(&Serial(13)), Some(Greater));

        // (i1 > i2 and i1 - i2 < 2^(SERIAL_BITS - 1))
        assert_eq!(Serial(13).partial_cmp(&Serial(12)), Some(Greater));
        assert_ne!(Serial(3_000_000_012).partial_cmp(&Serial(12)),
                   Some(Greater));
        
        // Er, I think that’s what’s left.
        assert_eq!(Serial(1).partial_cmp(&Serial(0x8000_0001)), None);
        assert_eq!(Serial(0x8000_0001).partial_cmp(&Serial(1)), None);
    }
}

