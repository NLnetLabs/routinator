//! Building JSON on the fly.

use std::fmt;
use crate::utils::fmt::WriteOrPanic;


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

impl JsonBuilder<'_> {
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
        write!(self.target, "{}", json_str(value));
        self.target.push('"');
    }

    pub fn member_raw(
        &mut self, key: impl fmt::Display, value: impl fmt::Display
    ) {
        self.append_key(key);
        write!(self.target, "{}", json_str(value));
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
        write!(self.target, "{}", json_str(value));
        self.target.push('"');
    }

    pub fn array_raw(&mut self, value: impl fmt::Display) {
        self.append_array_head();
        self.append_indent();
        write!(self.target, "{}", json_str(value));
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
        write!(self.target, "{}", json_str(key));
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


//------------ json_str -----------------------------------------------------

pub fn json_str(val: impl fmt::Display) -> impl fmt::Display {
    struct WriteJsonStr<'a, 'f>(&'a mut fmt::Formatter<'f>);

    impl fmt::Write for WriteJsonStr<'_, '_> {
        fn write_str(&mut self, mut s: &str) -> fmt::Result {
            while let Some(idx) = s.find(['"', '\\']) {
                self.0.write_str(&s[..idx])?;
                self.0.write_str("\\")?;
                write!(self.0, "{}", char::from(s.as_bytes()[idx]))?;
                s = &s[idx + 1..];
            }
            self.0.write_str(s)
        }
    }

    struct JsonStr<T>(T);

    impl<T: fmt::Display> fmt::Display for JsonStr<T> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            use std::fmt::Write;

            write!(&mut WriteJsonStr(f), "{}", self.0)
        }
    }

    JsonStr(val)
}


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_json_str() {
        assert_eq!(
            format!("{}", json_str("foo")).as_str(),
            "foo"
        );
        assert_eq!(
            format!("{}", json_str("f\"oo")).as_str(),
            "f\\\"oo"
        );
        assert_eq!(
            format!("{}", json_str("f\\oo")).as_str(),
            "f\\\\oo"
        );
        assert_eq!(
            format!("{}", json_str("\\oo")).as_str(),
            "\\\\oo"
        );
        assert_eq!(
            format!("{}", json_str("foo\\")).as_str(),
            "foo\\\\"
        );
    }
}

