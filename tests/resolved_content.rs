use agenthooksprotocol::{
    content::{AuthorizedScope, ContentContext, ContentStore, MemoryContentStore, UploadError},
    generated::ContentReference,
};
use serde_json::{Value, json};
use std::{sync::Arc, sync::Mutex};

fn item(reference: Value) -> Value {
    json!({"id":"stable", "kind":"message", "mediaType":"text/plain", "role":"assistant", "selection":"body", "body":reference, "category":"reasoning", "parentItemId":"owner", "synthesized":true})
}

#[test]
fn shared_store_is_immutable_scoped_and_bounded() {
    let store = MemoryContentStore::new(8, 12, 2);
    let shared = store.clone();
    let context = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("secret-scope"),
    };
    let first = context.put(b"first").unwrap();
    assert!(!first.to_string().contains("secret-scope"));
    let retained = context.resolve(&first).unwrap();
    let second = ContentContext {
        store: &shared,
        scope: context.scope.clone(),
    }
    .put(b"second")
    .unwrap();
    assert_ne!(first["ref"], second["ref"]);
    assert_eq!(&*retained, b"first");
    assert_eq!(context.put(b"x"), Err(UploadError::Capacity));
    assert_eq!(context.put(b"123456789"), Err(UploadError::TooLarge));
    let other = ContentContext {
        store: &shared,
        scope: AuthorizedScope::new("other"),
    };
    assert_eq!(other.resolve(&first), Err(UploadError::Unavailable));
    let mut wrong = first.clone();
    wrong["size"] = json!(6);
    assert_eq!(context.resolve(&wrong), Err(UploadError::Descriptor));
    wrong = first;
    wrong["extra"] = json!(true);
    assert_eq!(context.resolve(&wrong), Err(UploadError::Descriptor));
}

struct Host {
    reads: Mutex<usize>,
    backing: MemoryContentStore,
    lie_read: bool,
    lie_write: bool,
}
impl ContentStore for Host {
    fn resolve(
        &self,
        scope: &AuthorizedScope,
        reference: &ContentReference,
    ) -> Result<Arc<[u8]>, UploadError> {
        *self.reads.lock().unwrap() += 1;
        if self.lie_read {
            Ok(Arc::from(&b"evil"[..]))
        } else {
            self.backing.resolve(scope, reference)
        }
    }
    fn put(
        &self,
        scope: &AuthorizedScope,
        bytes: Arc<[u8]>,
    ) -> Result<ContentReference, UploadError> {
        self.backing.put(
            scope,
            if self.lie_write {
                Arc::from(&b"evil"[..])
            } else {
                bytes
            },
        )
    }
}
#[test]
fn writes_verify_readback_but_resolution_trusts_the_scoped_store() {
    for (lie_read, lie_write) in [(true, false), (false, true)] {
        let host = Host {
            reads: Mutex::new(0),
            backing: MemoryContentStore::new(128, 256, 8),
            lie_read,
            lie_write,
        };
        let context = ContentContext {
            store: &host,
            scope: AuthorizedScope::new("a"),
        };
        assert_eq!(context.put(b"good"), Err(UploadError::Descriptor));
        let reference = host
            .backing
            .put(&context.scope, Arc::from(&b"good"[..]))
            .unwrap();
        if lie_read {
            assert_eq!(
                context
                    .resolve(&serde_json::to_value(reference).unwrap())
                    .unwrap()
                    .as_ref(),
                b"evil"
            );
        }
    }
}
#[test]
fn views_do_not_fetch_and_body_gaps_fail_closed() {
    let host = Host {
        reads: Mutex::new(0),
        backing: MemoryContentStore::new(128, 256, 8),
        lie_read: true,
        lie_write: false,
    };
    let context = ContentContext {
        store: &host,
        scope: AuthorizedScope::new("a"),
    };
    for selection in ["metadata", "omit"] {
        assert_eq!(
            context
                .resolve_selected(&json!({"selection":selection}))
                .unwrap(),
            None
        );
    }
    assert_eq!(
        context.resolve_selected(&json!({"selection":"body", "gap":{"reason":"unavailable"}})),
        Err(UploadError::Unavailable)
    );
    assert_eq!(*host.reads.lock().unwrap(), 0);
}
#[test]
fn bounded_text_and_json_verify_utf8_and_bytes() {
    let store = MemoryContentStore::new(128, 512, 8);
    let context = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("a"),
    };
    let reference = context.put(br#"{"key":true}"#).unwrap();
    assert_eq!(
        context.resolve_json(&reference, 128).unwrap(),
        json!({"key":true})
    );
    assert_eq!(
        context.resolve_text(&reference, 1),
        Err(UploadError::TooLarge)
    );
    let invalid = context.put(&[0xff]).unwrap();
    assert_eq!(
        context.resolve_text(&invalid, 128),
        Err(UploadError::Descriptor)
    );
    assert_eq!(
        context.resolve_json(&invalid, 128),
        Err(UploadError::Descriptor)
    );
}
#[test]
fn rewrites_preserve_metadata_and_staged_failure_does_not_publish() {
    let store = MemoryContentStore::new(8, 32, 3);
    let context = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("a"),
    };
    let original = item(context.put(b"old").unwrap());
    let saved = original.clone();
    let rewritten = context.rewrite_body(&original, b"new").unwrap();
    for key in [
        "id",
        "role",
        "category",
        "parentItemId",
        "synthesized",
        "selection",
        "kind",
        "mediaType",
    ] {
        assert_eq!(rewritten[key], original[key]);
    }
    assert!(rewritten.get("size").is_none());
    assert!(rewritten.get("sha256").is_none());
    assert_eq!(
        &*context.resolve_selected(&rewritten).unwrap().unwrap(),
        b"new"
    );
    let result = context.rewrite_bodies(&[(&original, b"one"), (&original, b"two")]);
    assert_eq!(result, Err(UploadError::Capacity));
    assert_eq!(original, saved);
    assert_eq!(
        &*context.resolve_selected(&original).unwrap().unwrap(),
        b"old"
    );
    let mut wrong = original;
    wrong["size"] = json!(99);
    assert_eq!(
        context.resolve_selected(&wrong),
        Err(UploadError::Descriptor)
    );
}

#[test]
fn references_reject_deprecated_metadata_and_limits_use_stored_bytes() {
    let store = MemoryContentStore::new(128, 512, 8);
    let context = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("a"),
    };
    let original = context.put(b"abc").unwrap();
    assert_eq!(original.as_object().unwrap().len(), 1);
    assert_eq!(context.resolve_text(&original, 3).unwrap(), "abc");
    assert_eq!(
        context.resolve_limited(&original, 2),
        Err(UploadError::TooLarge)
    );
    for (field, value) in [
        ("size", json!(3)),
        ("size", json!(3.0)),
        ("sha256", json!("0".repeat(64))),
    ] {
        let mut reference = original.clone();
        reference[field] = value.clone();
        assert_eq!(context.resolve(&reference), Err(UploadError::Descriptor));
        let mut selected = item(original.clone());
        selected[field] = value;
        assert_eq!(
            context.resolve_selected(&selected),
            Err(UploadError::Descriptor)
        );
    }
}
