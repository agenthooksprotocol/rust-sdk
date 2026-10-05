use agenthooksprotocol::{
    content::{AuthorizedScope, ContentContext, ContentStore, MemoryContentStore, UploadError},
    generated::ContentReference,
};
use serde_json::{Value, json};
use std::{cell::Cell, sync::Arc};

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
    reads: Cell<usize>,
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
        self.reads.set(self.reads.get() + 1);
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
fn host_store_is_not_authoritative_for_digests() {
    for (lie_read, lie_write) in [(true, false), (false, true)] {
        let host = Host {
            reads: Cell::new(0),
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
                context.resolve(&serde_json::to_value(reference).unwrap()),
                Err(UploadError::Descriptor)
            );
        }
    }
}
#[test]
fn views_do_not_fetch_and_body_gaps_fail_closed() {
    let host = Host {
        reads: Cell::new(0),
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
    assert_eq!(host.reads.get(), 0);
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
    assert_eq!(rewritten["size"], rewritten["body"]["size"]);
    assert_eq!(rewritten["sha256"], rewritten["body"]["sha256"]);
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
fn integral_numeric_spellings_verify_without_rewriting_descriptors() {
    let store = MemoryContentStore::new(128, 512, 8);
    let context = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("a"),
    };
    let original = context.put(b"abc").unwrap();
    for spelling in ["3", "3.0", "3e0", "30e-1"] {
        let size: Value = serde_json::from_str(spelling).unwrap();
        let mut reference = original.clone();
        reference["size"] = size.clone();
        let retained = reference.clone();
        assert_eq!(&*context.resolve(&reference).unwrap(), b"abc");
        assert_eq!(context.resolve_text(&reference, 3).unwrap(), "abc");
        assert_eq!(
            context.resolve_limited(&reference, 2),
            Err(UploadError::TooLarge)
        );
        let mut selected = item(reference.clone());
        selected["size"] = size;
        assert_eq!(
            &*context.resolve_selected(&selected).unwrap().unwrap(),
            b"abc"
        );
        assert_eq!(reference, retained);
    }
    for spelling in ["3.1", "-3", "9007199254740992", "3.0000000000000001"] {
        let size: Value = serde_json::from_str(spelling).unwrap();
        let mut reference = original.clone();
        reference["size"] = size.clone();
        assert_eq!(context.resolve(&reference), Err(UploadError::Descriptor));
        let mut selected = item(original.clone());
        selected["size"] = size;
        assert_eq!(
            context.resolve_selected(&selected),
            Err(UploadError::Descriptor)
        );
    }
}
