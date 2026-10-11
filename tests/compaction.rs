use agenthooksprotocol::{
    compaction::{capabilities, selected_text},
    content::{AuthorizedScope, ContentContext, MemoryContentStore},
};
use serde_json::json;

#[test]
fn selected_inline_text_preserves_order_and_exact_bytes() {
    let store = MemoryContentStore::new(4096, 65536, 100);
    let content = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("compaction"),
    };
    let parts = json!([
        {"id":"first","kind":"text","mediaType":"text/plain","selection":"body","text":" original\r\n"},
        {"id":"second","kind":"text","mediaType":"text/plain","selection":"body","text":"λ "}
    ]);
    assert_eq!(selected_text(&parts, &content).unwrap(), " original\r\nλ ");
}

#[test]
fn selected_text_rejects_gaps_unselected_text_and_legacy_references() {
    let store = MemoryContentStore::new(4096, 65536, 100);
    let content = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("compaction"),
    };
    for parts in [
        json!({"id":"summary","ref":"content-1"}),
        json!([{"selection":"none","text":"hidden"}]),
        json!([{"selection":"body","gap":{},"text":"incomplete"}]),
        json!([{"selection":"body","ref":"content-1"}]),
    ] {
        assert!(selected_text(&parts, &content).is_err());
    }
}

#[test]
fn boundary_capabilities_do_not_grant_after_return_or_denial() {
    let before = capabilities("before", false).unwrap();
    let after = capabilities("after", false).unwrap();
    assert!(
        before["effects"]
            .as_array()
            .unwrap()
            .contains(&json!("return"))
    );
    assert!(
        before["effects"]
            .as_array()
            .unwrap()
            .contains(&json!("deny"))
    );
    assert!(
        !after["effects"]
            .as_array()
            .unwrap()
            .contains(&json!("return"))
    );
    assert!(
        !after["effects"]
            .as_array()
            .unwrap()
            .contains(&json!("deny"))
    );
    assert_eq!(capabilities("after", true).unwrap()["effects"], json!([]));
    assert!(capabilities("unknown", false).is_err());
}
