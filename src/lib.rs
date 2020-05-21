//!
//! Parser for a [decentralized identifier](https://w3c.github.io/did-core)
//!
//! Specification:
//! ```text
//! did                = "did:" method-name ":" method-specific-id
//! method-name        = 1*method-char
//! method-char        = %x61-7A / DIGIT
//! method-specific-id = *idchar *( ":" *idchar )
//! idchar             = ALPHA / DIGIT / "." / "-" / "_"
//! did-url            = did *( ";" param ) path-abempty [ "?" query ]
//!                      [ "#" fragment ]
//! param              = param-name [ "=" param-value ]
//! param-name         = 1*param-char
//! param-value        = *param-char
//! param-char         = ALPHA / DIGIT / "." / "-" / "_" / ":" /
//!                      pct-encoded
//!```
//! *Note: support for `pct-encoded` is currently missing*
//!
//! Example of use:
//! ```rust
//!  use did_parser::Did;
//!
//!  let example_did = "did:example:21tDAKCERh95uGgKbJNHYp;name=dave/a/b/c?query=hello&say=what#key1";
//!  
//!  let (_, did)= Did::parse(example_did).unwrap();
//!  assert_eq!("21tDAKCERh95uGgKbJNHYp", did.id.clone());
//!  assert_eq!("example", did.method.clone());
//!        
//!  // method params
//!  let map = did.method_params.unwrap();
//!  assert_eq!(Some(&"dave"), map.get("name"));
//!
//!  // path
//!  assert_eq!(vec!["a", "b", "c"], did.path.unwrap());
//!
//!  // query
//!  let map = did.query.unwrap();
//!  assert_eq!(Some(&"hello"), map.get("query"));
//!  assert_eq!(Some(&"what"), map.get("say"));
//!
//!  // fragment
//!  assert_eq!("key1", did.frag.unwrap());
//! ```
//!
use std::collections::HashMap;

use nom::{
    bytes::complete::{tag, take_while},
    char,
    character::{complete::char, is_alphanumeric, is_digit},
    combinator::{complete, map, opt},
    do_parse,
    error::ErrorKind,
    multi::separated_list,
    named,
    sequence::{preceded, tuple},
    Err, IResult,
};

/// Container for a DID
#[derive(Debug, Clone)]
pub struct Did<'a> {
    /// The method (registry) name
    pub method: &'a str,
    /// The actual identifier
    pub id: &'a str,
    /// A map of name/values pairs from a query: `?`. Each pair is
    /// separated with an '&'.  You only have a fragment '3' after
    /// a query (or the end of the uri);
    pub query: Option<HashMap<&'a str, &'a str>>,
    /// Value from a URI fragment: `#`. Note according to the IETF spec,
    /// if you have a fragment, you can't have nothing after it.
    pub frag: Option<&'a str>,
    /// URI path: `/a/b/c`
    pub path: Option<Vec<&'a str>>,
    /// Method specfic parameters delimited with a `;`. Ex: `;foo:bar=dave;lang=rust`
    /// If present, should be the first thing after the DID id.
    pub method_params: Option<HashMap<&'a str, &'a str>>,
}

impl<'a> Did<'a> {
    /// Parse a DID into a DID container. On `Ok` it will
    /// return (&str, Did) where &str is what's left of
    /// the unconsumed input value. This will be empty for `Ok`.
    ///
    /// The IResult approach is needed to fit in with the
    /// way the underlying parser's error control works.
    pub fn parse(value: &str) -> IResult<&str, Did> {
        match tuple((
            tag("did"),
            tag(":"),
            parse_method_name,
            tag(":"),
            parse_did_identifier,
            opt(complete(parse_method_specfic_uri)),
            opt(complete(parse_path_uri)),
            opt(complete(parse_query_uri)),
            opt(complete(parse_fragment_uri)),
        ))(value)
        {
            Ok((rest, (_, _, method, _, id, method_params, path, query, frag))) => {
                if rest.len() > 0 {
                    // something's wrong
                    return Err(Err::Error((
                        "parser failed. Probably a bad character",
                        ErrorKind::IsNot,
                    )));
                }
                Ok((
                    rest,
                    Did {
                        method,
                        id,
                        query,
                        frag,
                        path,
                        method_params,
                    },
                ))
            }

            Err(kind) => Err(kind),
        }
    }

    /// Verify a base DID is structually correct. This validates the format of:
    /// `did:method:id` it does not check URI elements and will fail if they exist.
    pub fn is_valid_base_did(value: &str) -> bool {
        match tuple((
            tag("did"),
            preceded(tag(":"), parse_method_name),
            preceded(tag(":"), parse_did_identifier),
        ))(value)
        {
            Ok((rest, (_, _, _))) => {
                if rest.len() > 0 {
                    // something's wrong
                    return false;
                }
                true
            }
            Err(_) => false,
        }
    }
}

// check if the char is lowercase alpha
fn is_lowercase(char: u8) -> bool {
    char >= 0x61 && char <= 0x7a
}

// Parse param name/values
// param              = param-name [ "=" param-value ]
// param-name         = 1*param-char
// param-value        = *param-char
// param-char         = ALPHA / DIGIT / "." / "-" / "_" / ":" /
// NOT SUPPORTED =>   pct-encoded
fn parse_param(value: &str) -> IResult<&str, &str> {
    take_while(|i| is_alphanumeric(i as u8) || i == '.' || i == '-' || i == '_' || i == ':')(value)
}

// Parses key/value pairs returning them as (key, value)
named!(parse_key_value_pair<&str, (&str, &str)>,
    do_parse!(
        key: parse_param >>
        char!('=') >>
        val: parse_param >>
        (key, val)
    )
);

// Name of the did method registry
//
// method-name: 1*method-char
// method-char  = %x61-7A / DIGIT
fn parse_method_name(value: &str) -> IResult<&str, &str> {
    if value.len() == 0 || value.starts_with(":") {
        return Err(Err::Error(("missing method name", ErrorKind::LengthValue)));
    }
    take_while(|i| is_lowercase(i as u8) || is_digit(i as u8))(value)
}

// method-specific-id = *idchar *( ":" *idchar )
// idchar             = ALPHA / DIGIT / "." / "-" / "_"
fn parse_did_identifier(value: &str) -> IResult<&str, &str> {
    if value.len() == 0 {
        return Err(Err::Error(("missing did id", ErrorKind::LengthValue)));
    }
    // How does this terminate?
    //  - when it hits a URI (returning 'rest')
    //  - or end of did
    // There's no real way to control this...?
    take_while(|c| is_alphanumeric(c as u8) || c == '.' || c == '-' || c == '_')(value)
}

// *** Parse did-url stuff below  *** //

// ';' parse method-specific URI parameters. May include many key/value pairs delimited with a ";"
fn parse_method_specfic_uri(value: &str) -> IResult<&str, HashMap<&str, &str>> {
    map(
        preceded(tag(";"), separated_list(char(';'), parse_key_value_pair)),
        |v: Vec<_>| v.into_iter().collect(),
    )(value)
}

// '/' parse a path returning a vector of 'segments' from the path
fn parse_path_uri(value: &str) -> IResult<&str, Vec<&str>> {
    map(
        preceded(
            tag("/"),
            separated_list(char('/'), take_while(|i| is_alphanumeric(i as u8))),
        ),
        |v: Vec<_>| v.into_iter().collect(),
    )(value)
}

// '?' parse a query.  Per the ietf spec: The query component is indicated by the first question
// mark ("?") character and terminated by a number sign ("#") character or by the end of the URI.
fn parse_query_uri(s: &str) -> IResult<&str, HashMap<&str, &str>> {
    map(
        preceded(tag("?"), separated_list(char('&'), parse_key_value_pair)),
        |v: Vec<_>| v.into_iter().collect(),
    )(s)
}

// '#' parse a fragment:
// According to the spec (https://tools.ietf.org/html/rfc3986) a fragment
// starts with a '#' and is terminated by the end of the uri (nothing after it)
fn parse_fragment_uri(s: &str) -> IResult<&str, &str> {
    match tuple((
        tag("#"),
        take_while(|i| is_alphanumeric(i as u8) || i == '/' || i == '?' || i == ':' || i == '@'),
    ))(s)
    {
        Ok((rest, (_, value))) => Ok((rest, value)),
        Err(kind) => Err(kind),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_base_did() {
        // Bueno
        assert!(Did::parse("did:example:21tDAKCERh95uGgKbJNHYp").is_ok());
        assert!(Did::parse("did:exa123ple:21tDAKCERh95uGgKbJNHYp").is_ok());
        assert!(Did::parse("did:555:21tDAKCERh95uGgKbJNHYp").is_ok());
        assert!(Did::parse("did:example:21tDAKC.ERh95uGgKbJNHYp").is_ok());
        assert!(Did::parse("did:example:21tDAKC-ERh95uGgKbJNHYp").is_ok());

        // needs 'did'
        assert!(Did::parse("di:example:21tDAKCERh95uGgKbJNHYp").is_err());
        assert!(Did::parse(":example:21tDAKCERh95uGgKbJNHYp").is_err());

        // method must be lowercase or digit only
        assert!(Did::parse("did:eXample:21tDAKCERh95uGgKbJNHYp").is_err());
        assert!(Did::parse("did:exam?ple:21tDAKCERh95uGgKbJNHYp").is_err());
        assert!(Did::parse("did:exam:ple:21tDAKCERh95uGgKbJNHYp").is_err());

        // ID can't contain odd characters
        assert!(Did::parse("did:example:21tDAKC&ERh95uGgKbJNHYp").is_err());
        assert!(Did::parse("did:example:21tDAKC*ERh95uGgKbJNHYp").is_err());

        // ... but URI prefixes in an ID will slide through... this is not
        // good...  This will parse OK.  But the ID is incorrect and it you'll
        // have a path '/'
        assert!(Did::parse("did:example:21tDAKC/ERh95uGgKbJNHYp").is_ok());
    }

    #[test]
    fn test_query() {
        let (_, did) = Did::parse("did:example:21tDAKCERh95uGgKbJNHYp?name=bob").unwrap();
        assert_eq!(Some(&"bob"), did.query.unwrap().get("name"));

        let (_, did1) =
            Did::parse("did:example:21tDAKCERh95uGgKbJNHYp?name=bob&lang=rust").unwrap();
        let map = did1.query.unwrap();
        assert_eq!(Some(&"bob"), map.get("name"));
        assert_eq!(Some(&"rust"), map.get("lang"));
    }

    #[test]
    fn test_path_frag() {
        let (_, did) = Did::parse("did:example:21tDAKCERh95uGgKbJNHYp/a/b/c").unwrap();
        assert_eq!(vec!["a", "b", "c"], did.path.unwrap());

        let (_, did1) = Did::parse("did:example:21tDAKCERh95uGgKbJNHYp/a/b/c#key1").unwrap();
        assert_eq!(vec!["a", "b", "c"], did1.path.unwrap());
        assert_eq!("key1", did1.frag.unwrap());

        let (_, did2) = Did::parse("did:example:21tDAKCERh95uGgKbJNHY#key1:key2").unwrap();
        assert_eq!("key1:key2", did2.frag.unwrap());
    }

    #[test]
    fn test_method_service() {
        let (_, did) = Did::parse("did:example:21tDAKCERh95uGgKbJNHYp;name=bob").unwrap();
        let map = did.method_params.unwrap();
        assert_eq!(Some(&"bob"), map.get("name"));

        let (_, did1) =
            Did::parse("did:example:21tDAKCERh95uGgKbJNHYp;name=bob;lang=rust").unwrap();
        let map = did1.method_params.unwrap();
        assert_eq!(Some(&"bob"), map.get("name"));
        assert_eq!(Some(&"rust"), map.get("lang"));
    }

    #[test]
    fn test_the_whole_enchilada() {
        let (_, did) = Did::parse(
            "did:example:21tDAKCERh95uGgKbJNHYp;name=dave/a/b/c?query=hello&say=what#key1",
        )
        .unwrap();
        // method params
        let map = did.method_params.unwrap();
        assert_eq!(Some(&"dave"), map.get("name"));

        // Path
        assert_eq!(vec!["a", "b", "c"], did.path.unwrap());

        // query
        let map = did.query.unwrap();
        assert_eq!(Some(&"hello"), map.get("query"));
        assert_eq!(Some(&"what"), map.get("say"));

        // Frag
        assert_eq!("key1", did.frag.unwrap());
    }

    #[test]
    fn test_container() {
        let (_, did) = Did::parse(
            "did:example:21tDAKCERh95uGgKbJNHYp;name=dave/a/b/c?query=hello&say=what#key1",
        )
        .unwrap();
        assert_eq!("21tDAKCERh95uGgKbJNHYp", did.id.clone());
        assert_eq!("example", did.method.clone());

        // method params
        let map = did.method_params.unwrap();
        assert_eq!(Some(&"dave"), map.get("name"));

        // Path
        assert_eq!(vec!["a", "b", "c"], did.path.unwrap());

        // query
        let map = did.query.unwrap();
        assert_eq!(Some(&"hello"), map.get("query"));
        assert_eq!(Some(&"what"), map.get("say"));

        // Frag
        assert_eq!("key1", did.frag.unwrap());
    }

    #[test]
    fn test_validate_base_did() {
        assert_eq!(
            false,
            Did::is_valid_base_did("did:EXAMPLE:21tDAKCERh95uGgKbJNHYp")
        );
        assert_eq!(
            false,
            Did::is_valid_base_did("did:exa*mple:21tDAKCERh95uGgKbJNHYp")
        );
        assert_eq!(
            false,
            Did::is_valid_base_did("example:21tDAKCERh95uGgKbJNHYp")
        );
        assert_eq!(
            false,
            Did::is_valid_base_did("did:example:21tDAK/CERh95uGgKbJNHYp")
        );
        assert_eq!(false, Did::is_valid_base_did("did:example:"));
        assert_eq!(
            false,
            Did::is_valid_base_did("did::21tDAKACERh95uGgKbJNHYp")
        );

        assert!(Did::is_valid_base_did("did:example:21tDAKCERh95uGgKbJNHYp"));
    }
}
