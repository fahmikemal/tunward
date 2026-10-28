//! The YAML parser behind every policy file: safe Rust, with bounded parsing work.

use serde::de::{DeserializeOwned, Error as _};
use serde::{Deserialize, Deserializer};
use std::io::Read;

fn options() -> serde_saphyr::Options {
    serde_saphyr::options! {
        // YAML 1.2 booleans, as the policy files have always been read: `yes`, `on` and `no` stay strings.
        strict_booleans: true,
        // A policy means exactly what it spells out; `<<` merges were never applied to it.
        merge_keys: serde_saphyr::MergeKeyPolicy::Error,
        // One-line errors with line and column, for logs and reload responses.
        with_snippet: false,
    }
}

pub(crate) fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, serde_saphyr::Error> {
    serde_saphyr::from_slice_with_options(bytes, options())
}

pub(crate) fn from_reader<T: DeserializeOwned>(reader: impl Read) -> Result<T, serde_saphyr::Error> {
    serde_saphyr::from_reader_with_options(reader, options())
}

/// Refuses a blank value (`port:`, `~` or `null`) where the field is not optional.
///
/// The parser reads a blank value as an empty list, mapping or struct. Where empty means "any" or
/// "no limit", that would turn a value left blank or commented out into the widest rule, so such
/// fields deserialize through this function: `[]` and `{}` still say "any" explicitly.
pub(crate) fn required<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)?
        .ok_or_else(|| D::Error::custom("a blank value is not allowed here; write [] or {} to mean empty"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Doc {
        #[serde(default)]
        name: String,
        #[serde(default)]
        flag: Option<bool>,
        #[serde(default)]
        items: HashMap<String, Vec<String>>,
        #[serde(default, deserialize_with = "required")]
        guarded: Vec<String>,
    }

    fn parse(yaml: &str) -> Result<Doc, String> {
        from_slice(yaml.as_bytes()).map_err(|error| error.to_string())
    }

    #[test]
    fn yaml_1_1_booleans_stay_strings() {
        assert_eq!(parse("name: yes").unwrap().name, "yes");
        assert!(parse("flag: yes").is_err());
        assert_eq!(parse("flag: true").unwrap().flag, Some(true));
    }

    #[test]
    fn duplicate_keys_are_refused_instead_of_the_last_one_winning() {
        assert!(parse("items: {a: [x], a: [y]}").unwrap_err().contains("duplicate"));
    }

    #[test]
    fn merge_keys_are_refused() {
        assert!(parse("items:\n  a: &base [x]\n  b:\n    <<: *base").is_err());
        assert!(parse("<<: {name: x}").is_err());
    }

    #[test]
    fn several_documents_are_refused() {
        assert!(parse("name: a\n---\nname: b").is_err());
    }

    #[test]
    fn a_required_field_refuses_blank_values_but_accepts_explicit_empty_ones() {
        for blank in ["guarded:", "guarded: ~", "guarded: null"] {
            assert!(parse(blank).unwrap_err().contains("blank value"), "{blank}");
        }
        assert_eq!(parse("guarded: []").unwrap().guarded, Vec::<String>::new());
        assert_eq!(parse("guarded: [a, 1]").unwrap().guarded, ["a", "1"]);
        assert_eq!(parse("name: a").unwrap().guarded, Vec::<String>::new());
    }

    #[test]
    fn errors_are_one_line_with_a_position() {
        let error = parse("name: a\nunknown: 1").unwrap_err();
        assert!(error.contains("unknown field") && error.contains("line 2"), "{error}");
        assert!(!error.contains('\n'), "{error}");
    }
}
