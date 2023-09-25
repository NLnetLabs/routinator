//! Utilities for dealing with HTTP.

use std::fmt;
use chrono::{DateTime, Local, Utc};
use chrono::format::{Item, Fixed, Numeric, Pad};


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
#[allow(clippy::question_mark)] // False positive.
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


//------------ Constructing ISO Dates ----------------------------------------


pub fn format_iso_date(date: DateTime<Utc>) -> impl fmt::Display {
    const UTC_ISO_DATE: &[Item<'static>] = &[
        Item::Numeric(Numeric::Year, Pad::Zero),
        Item::Literal("-"),
        Item::Numeric(Numeric::Month, Pad::Zero),
        Item::Literal("-"),
        Item::Numeric(Numeric::Day, Pad::Zero),
        Item::Literal("T"),
        Item::Numeric(Numeric::Hour, Pad::Zero),
        Item::Literal(":"),
        Item::Numeric(Numeric::Minute, Pad::Zero),
        Item::Literal(":"),
        Item::Numeric(Numeric::Second, Pad::Zero),
        Item::Literal("Z"),
    ];

    date.format_with_items(UTC_ISO_DATE.iter())
}

pub fn format_local_iso_date(date: DateTime<Local>) -> impl fmt::Display {
    const LOCAL_ISO_DATE: &[Item<'static>] = &[
        Item::Numeric(Numeric::Year, Pad::Zero),
        Item::Literal("-"),
        Item::Numeric(Numeric::Month, Pad::Zero),
        Item::Literal("-"),
        Item::Numeric(Numeric::Day, Pad::Zero),
        Item::Literal("T"),
        Item::Numeric(Numeric::Hour, Pad::Zero),
        Item::Literal(":"),
        Item::Numeric(Numeric::Minute, Pad::Zero),
        Item::Literal(":"),
        Item::Numeric(Numeric::Second, Pad::Zero),
    ];

    date.format_with_items(LOCAL_ISO_DATE.iter())
}


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_parse_http_date() {
        let date = Utc.from_utc_datetime(
            &chrono::naive::NaiveDate::from_ymd_opt(
                1994, 11, 6
            ).unwrap().and_hms_opt(8, 49, 37).unwrap()
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
