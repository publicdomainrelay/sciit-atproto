//! The published Lexicon has to describe the method that is actually served.
//!
//! A Lexicon is a promise to callers: an AT Protocol client reads it to know
//! the NSID, whether the method is a query or a procedure, and which fields
//! come back. A Lexicon that drifts from the handler is worse than none,
//! because it is read as authoritative. `cargo test` cannot type-check a JSON
//! schema against a handler, but it can hold the parts that would break a
//! client -- the identifier, the method type, the input encoding, and the
//! presence of every field the handler returns.

use std::path::PathBuf;

use scitt_atproto_signer::config::DEFAULT_NSID;
use serde_json::Value;

/// The Lexicon document, parsed.
fn lexicon() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("lexicons/blue/scitt/sign.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} could not be read: {error}", path.display()));
    serde_json::from_str(&text).expect("the Lexicon is JSON")
}

/// The document is valid Lexicon: the envelope fields, and the identifier
/// matching the path it is filed under.
#[test]
fn the_lexicon_envelope_is_well_formed() {
    let lexicon = lexicon();
    assert_eq!(lexicon["lexicon"], 1);
    assert_eq!(lexicon["id"], DEFAULT_NSID);

    // An NSID's authority is its first two segments as reversed domain
    // labels, and a Lexicon record is published at the NSID's own path. Both
    // are easy to get wrong and impossible to fix after publishing.
    let id = lexicon["id"].as_str().expect("an id");
    assert_eq!(
        PathBuf::from(format!("lexicons/{}.json", id.replace('.', "/"))),
        PathBuf::from("lexicons/blue/scitt/sign.json")
    );
}

/// `sign` is a procedure: it takes a body, and it registers something. A
/// client that read `query` here would send no body and get a 400.
#[test]
fn the_method_is_a_procedure_with_a_json_body() {
    let main = &lexicon()["defs"]["main"];
    assert_eq!(main["type"], "procedure");
    assert_eq!(main["input"]["encoding"], "application/json");
    assert_eq!(main["output"]["encoding"], "application/json");
}

/// Every field the handler returns is named, and every field the schema
/// requires is one the handler returns. The second half is what would make a
/// client reject a perfectly good response.
#[test]
fn the_output_schema_names_what_the_handler_returns() {
    let lexicon = lexicon();
    let output = &lexicon["defs"]["main"]["output"]["schema"];

    let Some(required) = output["required"].as_array() else {
        panic!("the output schema requires nothing, which describes no contract");
    };
    let required: Vec<&str> = required.iter().filter_map(Value::as_str).collect();

    for field in [
        "did",
        "repository",
        "contentType",
        "statement",
        "transparentStatement",
        "inlineSignature",
        "contentCid",
        "signedRecord",
    ] {
        assert!(
            required.contains(&field),
            "the output schema does not require `{field}`"
        );
        assert!(
            output["properties"][field].is_object(),
            "the output schema does not describe `{field}`"
        );
    }
}

/// The two nested objects are referenced by name, so a change to one of them
/// is a change in one place.
#[test]
fn the_nested_objects_are_defined_and_referenced() {
    let lexicon = lexicon();
    let output = &lexicon["defs"]["main"]["output"]["schema"];

    for (field, definition) in [
        ("statement", "statement"),
        ("transparentStatement", "transparentStatement"),
    ] {
        assert_eq!(output["properties"][field]["type"], "ref");
        assert_eq!(output["properties"][field]["ref"], format!("#{definition}"));

        let defs = &lexicon["defs"][definition];
        assert_eq!(defs["type"], "object");
        assert!(
            defs["required"].is_array(),
            "`{definition}` requires nothing"
        );
    }
}

/// The errors the schema names are the errors the handler can return. A
/// client switches on these.
#[test]
fn the_declared_errors_are_the_ones_the_handler_returns() {
    let lexicon = lexicon();
    let errors = lexicon["defs"]["main"]["errors"]
        .as_array()
        .expect("an errors array");
    let names: Vec<&str> = errors.iter().filter_map(|e| e["name"].as_str()).collect();

    for name in ["InvalidRequest", "InternalServerError", "UpstreamFailure"] {
        assert!(names.contains(&name), "`{name}` is not declared: {names:?}");
    }
}
