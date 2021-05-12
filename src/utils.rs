//! Various useful things.
//!
use std::{fmt, str};
use std::fmt::Write;
use std::net::IpAddr;
use std::str::FromStr;
use chrono::{DateTime, Utc};
use chrono::format::{Item, Fixed, Numeric, Pad};
use rpki::uri;


//------------ str_from_ascii ------------------------------------------------

/// Converts a sequence of ASCII octets into a str.
pub fn str_from_ascii(src: &[u8]) -> Result<&str, AsciiError> {
    if src.is_ascii() {
        Ok(unsafe { str::from_utf8_unchecked(src) })
    }
    else {
        Err(AsciiError)
    }
}


//------------ AsciiError ----------------------------------------------------

pub struct AsciiError;


//------------ UriExt --------------------------------------------------------

/// An extension trait for URI kind of types.
pub trait UriExt {
    fn get_authority(&self) -> &str;

    /// Returns whether the URI has a dubious authority.
    ///
    /// A dubious authority is a hostname portion of the URI that definitely
    /// cannot be reached from the public Internet or that shouldn’t be.
    ///
    /// Currently, we filter out the reserved name `localhost`, anything that
    /// uses an IP address as the host name, and anything that specifies an
    /// explicit port.
    fn has_dubious_authority(&self) -> bool {
        let authority = self.get_authority();

        // Filter out "localhost"
        if authority == "localhost" {
            return true;
        }

        // Filter out anything that contains a colon.
        if authority.contains(':') {
            return true
        }

        // Filter out anything that parses as an IP address.
        //
        // Socket addresses have gone via the previous rule already.
        if IpAddr::from_str(authority).is_ok() {
            return true
        }

        false
    }
}

impl UriExt for uri::Https {
    fn get_authority(&self) -> &str {
        self.authority()
    }
}

impl UriExt for uri::Rsync {
    fn get_authority(&self) -> &str {
        self.authority()
    }
}


//------------ Parsing and Constructing HTTP Dates ---------------------------

/// Definition of the preferred date format (aka IMF-fixdate).
///
/// The definition allows for relaxed parsing: It accepts additional white
/// space and ignores case for textual representations. It does, however,
/// construct the correct representation when formatting.
const IMF_FIXDATE: &[Item<'static>] = &[
    Item::Space(""),
    Item::Fixed(Fixed::ShortWeekdayName),
    Item::Space(""),
    Item::Literal(","),
    Item::Space(" "),
    Item::Numeric(Numeric::Day, Pad::Zero),
    Item::Space(" "),
    Item::Fixed(Fixed::ShortMonthName),
    Item::Space(" "),
    Item::Numeric(Numeric::Year, Pad::Zero),
    Item::Space(" "),
    Item::Numeric(Numeric::Hour, Pad::Zero),
    Item::Literal(":"),
    Item::Numeric(Numeric::Minute, Pad::Zero),
    Item::Literal(":"),
    Item::Numeric(Numeric::Second, Pad::Zero),
    Item::Space(" "),
    Item::Literal("GMT"),
    Item::Space(""),
];

/// Definition of the obsolete RFC850 date format..
const RFC850_DATE: &[Item<'static>] = &[
    Item::Space(""),
    Item::Fixed(Fixed::LongWeekdayName),
    Item::Space(""),
    Item::Literal(","),
    Item::Space(" "),
    Item::Numeric(Numeric::Day, Pad::Zero),
    Item::Literal("-"),
    Item::Fixed(Fixed::ShortMonthName),
    Item::Literal("-"),
    Item::Numeric(Numeric::YearMod100, Pad::Zero),
    Item::Space(" "),
    Item::Numeric(Numeric::Hour, Pad::Zero),
    Item::Literal(":"),
    Item::Numeric(Numeric::Minute, Pad::Zero),
    Item::Literal(":"),
    Item::Numeric(Numeric::Second, Pad::Zero),
    Item::Space(" "),
    Item::Literal("GMT"),
    Item::Space(""),
];

/// Definition of the obsolete asctime date format.
const ASCTIME_DATE: &[Item<'static>] = &[
    Item::Space(""),
    Item::Fixed(Fixed::ShortWeekdayName),
    Item::Space(" "),
    Item::Fixed(Fixed::ShortMonthName),
    Item::Space(" "),
    Item::Numeric(Numeric::Day, Pad::Space),
    Item::Space(" "),
    Item::Numeric(Numeric::Hour, Pad::Zero),
    Item::Literal(":"),
    Item::Numeric(Numeric::Minute, Pad::Zero),
    Item::Literal(":"),
    Item::Numeric(Numeric::Second, Pad::Zero),
    Item::Space(" "),
    Item::Numeric(Numeric::Year, Pad::Zero),
    Item::Space(""),
];

/// Parses an HTTP date.
///
/// Since all date format allow ASCII characters only, this expects a str.
/// If it cannot parse the date, it simply returns `None`.
pub fn parse_http_date(date: &str) -> Option<DateTime<Utc>> {
    use chrono::format::{Parsed, parse};

    let mut parsed = Parsed::new();
    if parse(&mut parsed, date, IMF_FIXDATE.iter()).is_err() {
        parsed = Parsed::new();
        if parse(&mut parsed, date, RFC850_DATE.iter()).is_err() {
            parsed = Parsed::new();
            if parse(&mut parsed, date, ASCTIME_DATE.iter()).is_err() {
                return None
            }
        }
    }
    parsed.to_datetime_with_timezone(&Utc).ok()
}

pub fn format_http_date(date: DateTime<Utc>) -> String {
    date.format_with_items(IMF_FIXDATE.iter()).to_string()
}


//------------ JsonBuilder ---------------------------------------------------

/// A helper type for building a JSON-encoded string on the fly.
///
/// Note that the builder only supports strings without control characters.
pub struct JsonBuilder<'a> {
    target: &'a mut String,
    indent: usize,
    empty: bool,
}

impl JsonBuilder<'static> {
    pub fn build<F: FnOnce(&mut JsonBuilder)>(op: F) -> String {
        let mut target = String::new();
        JsonBuilder {
            target: &mut target, indent: 0, empty: true
        }.array_object(op);
        target
    }
}

impl<'a> JsonBuilder<'a> {
    pub fn member_object<F: FnOnce(&mut JsonBuilder)>(
        &mut self, key: impl fmt::Display, op: F
    ) {
        self.append_key(key);
        self.target.push_str("{\n");
        op(&mut JsonBuilder {
            target: self.target,
            indent: self.indent + 1,
            empty: true
        });
        self.target.push('\n');
        self.append_indent();
        self.target.push('}');
    }

    pub fn member_array<F: FnOnce(&mut JsonBuilder)>(
        &mut self, key: impl fmt::Display, op: F
    ) {
        self.append_key(key);
        self.target.push_str("[\n");
        op(&mut JsonBuilder {
            target: self.target,
            indent: self.indent + 1,
            empty: true
        });
        self.target.push('\n');
        self.append_indent();
        self.target.push(']');
    }

    pub fn member_str(
        &mut self, key: impl fmt::Display, value: impl fmt::Display
    ) {
        self.append_key(key);
        self.target.push('"');
        write!(JsonString { target: self.target }, "{}", value).unwrap();
        self.target.push('"');
    }

    pub fn member_raw(
        &mut self, key: impl fmt::Display, value: impl fmt::Display
    ) {
        self.append_key(key);
        write!(JsonString { target: self.target }, "{}", value).unwrap();
    }

    pub fn array_object<F: FnOnce(&mut JsonBuilder)>(&mut self, op: F) {
        self.append_array_head();
        self.append_indent();
        self.target.push_str("{\n");
        op(&mut JsonBuilder {
            target: self.target,
            indent: self.indent + 1,
            empty: true
        });
        self.target.push('\n');
        self.append_indent();
        self.target.push('}');
    }

    pub fn array_array<F: FnOnce(&mut JsonBuilder)>(&mut self, op: F) {
        self.append_array_head();
        self.append_indent();
        self.target.push_str("[\n");
        op(&mut JsonBuilder {
            target: self.target,
            indent: self.indent + 1,
            empty: true
        });
        self.target.push('\n');
        self.append_indent();
        self.target.push(']');
    }

    pub fn array_str(&mut self, value: impl fmt::Display) {
        self.append_array_head();
        self.append_indent();
        self.target.push('"');
        write!(JsonString { target: self.target }, "{}", value).unwrap();
        self.target.push('"');
    }

    pub fn array_raw(&mut self, value: impl fmt::Display) {
        self.append_array_head();
        self.append_indent();
        write!(JsonString { target: self.target }, "{}", value).unwrap();
    }

    fn append_key(&mut self, key: impl fmt::Display) {
        if self.empty {
            self.empty = false
        }
        else {
            self.target.push_str(",\n");
        }
        self.append_indent();
        self.target.push('"');
        write!(JsonString { target: self.target }, "{}", key).unwrap();
        self.target.push('"');
        self.target.push_str(": ");
    }

    fn append_array_head(&mut self) {
        if self.empty {
            self.empty = false
        }
        else {
            self.target.push_str(",\n");
        }
    }

    fn append_indent(&mut self) {
        for _ in 0..self.indent {
            self.target.push_str("   ");
        }
    }
}


//------------ JsonString ----------------------------------------------------

struct JsonString<'a> {
    target: &'a mut String,
}

impl<'a> fmt::Write for JsonString<'a> {
    fn write_str(&mut self, mut s: &str) -> Result<(), fmt::Error> {
        while let Some(idx) = s.find(|ch| ch == '"' || ch == '\\') {
            self.target.push_str(&s[..idx]);
            self.target.push('\\');
            self.target.push(char::from(s.as_bytes()[idx]));
            s = &s[idx + 1..];
        }
        self.target.push_str(s);
        Ok(())
    }
}


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_http_date() {
        let date = DateTime::<Utc>::from_utc(
            chrono::naive::NaiveDate::from_ymd(
                1994, 11, 6
            ).and_hms(8, 49, 37),
            Utc
        );

        assert_eq!(
            parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(date)
        );
        assert_eq!(
            parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT"),
            Some(date)
        );
        assert_eq!(
            parse_http_date("Sun Nov  6 08:49:37 1994"),
            Some(date)
        );
    }
}
