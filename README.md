# DID Parser

A Rust parser for a [decentralized identifier](https://w3c.github.io/did-core)

## How to use
```rust
  use did_parser::Did;
 
  let example_did = "did:example:21tDAKCERh95uGgKbJNHYp;name=dave/a/b/c?query=hello&say=what#key1";  
  let (_, did)= Did::parse(example_did).unwrap();
  assert_eq!("21tDAKCERh95uGgKbJNHYp", did.id.clone());
  assert_eq!("example", did.method.clone());
        
  // method params
  let map = did.method_params.unwrap();
  assert_eq!(Some(&"dave"), map.get("name"));

  // path
  assert_eq!(vec!["a", "b", "c"], did.path.unwrap());

  // query 
  let map = did.query.unwrap();
  assert_eq!(Some(&"hello"), map.get("query"));
  assert_eq!(Some(&"what"), map.get("say"));

  // fragment
  assert_eq!("key1", did.frag.unwrap()); 
```
