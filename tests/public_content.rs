use agenthooksprotocol::{
    content::{AuthorizedScope, UploadCredential, UploadError, UploadReceiver, Uploader},
    transport::{Http, Request, Response, TransportError},
};
use futures::executor::block_on;
use serde_json::json;
use std::{collections::BTreeMap, future::Future, pin::Pin, sync::Mutex};

type Authorizer = fn(&Request) -> Result<AuthorizedScope, UploadError>;
struct Local(Mutex<UploadReceiver<Authorizer>>);
impl Http for Local {
    fn send(
        &self,
        request: Request,
    ) -> Pin<Box<dyn Future<Output = Result<Response, TransportError>> + Send + '_>> {
        Box::pin(async move { Ok(self.0.lock().unwrap().handle(request)) })
    }
}
fn authorize(request: &Request) -> Result<AuthorizedScope, UploadError> {
    match request.headers.get("authorization").map(String::as_str) {
        Some("Bearer upload-a") => Ok(AuthorizedScope::new("tenant-a")),
        Some("Bearer upload-b") => Ok(AuthorizedScope::new("tenant-b")),
        Some("Bearer valid-not-authorized") => Err(UploadError::Forbidden),
        _ => Err(UploadError::Unauthorized),
    }
}
fn local() -> Local {
    Local(Mutex::new(UploadReceiver::new(
        authorize as Authorizer,
        "https://uploads.test/raw?purpose=hook",
        128,
        512,
        4,
    )))
}
#[test]
fn exact_binary_bytes_scoped_immutable_and_receiver_allocated() {
    let local = local();
    let uploader = Uploader::new(
        &local,
        "https://uploads.test/raw?purpose=hook",
        128,
        Some(UploadCredential::bearer("upload-a").unwrap()),
        false,
    )
    .unwrap();
    let bytes = [0, 255, 13, 10, 128];
    let reference = block_on(uploader.upload(&bytes)).unwrap();
    let retained = local
        .0
        .lock()
        .unwrap()
        .resolve(&AuthorizedScope::new("tenant-a"), &reference)
        .unwrap();
    assert_eq!(&*retained, bytes);
    assert!(matches!(
        local
            .0
            .lock()
            .unwrap()
            .resolve(&AuthorizedScope::new("tenant-b"), &reference),
        Err(UploadError::Unavailable)
    ));
    let mut tampered = reference.clone();
    tampered.sha256 = "a".repeat(64);
    assert!(matches!(
        local
            .0
            .lock()
            .unwrap()
            .resolve(&AuthorizedScope::new("tenant-a"), &tampered),
        Err(UploadError::Descriptor)
    ));
    let second = block_on(uploader.upload(b"changed")).unwrap();
    assert_ne!(reference.ref_, second.ref_);
    assert_eq!(&*retained, bytes);
}
#[test]
fn no_implicit_event_credentials_or_scope_from_reference() {
    let local = local();
    let uploader = Uploader::new(
        &local,
        "https://uploads.test/raw?purpose=hook",
        128,
        None,
        false,
    )
    .unwrap();
    assert!(matches!(
        block_on(uploader.upload(b"abc")),
        Err(UploadError::Http { status: 401, .. })
    ));
    let uploader = Uploader::new(
        &local,
        "https://uploads.test/raw?purpose=hook",
        128,
        Some(UploadCredential::bearer("valid-not-authorized").unwrap()),
        false,
    )
    .unwrap();
    assert!(matches!(
        block_on(uploader.upload(b"abc")),
        Err(UploadError::Http { status: 403, .. })
    ));
    assert!(
        !format!("{:?}", UploadCredential::bearer("secret-token").unwrap())
            .contains("secret-token")
    );
}
struct Fixed(Response);
impl Http for Fixed {
    fn send(
        &self,
        _: Request,
    ) -> Pin<Box<dyn Future<Output = Result<Response, TransportError>> + Send + '_>> {
        Box::pin(async {
            Ok(Response {
                status: self.0.status,
                headers: self.0.headers.clone(),
                body: self.0.body.clone(),
            })
        })
    }
}
#[test]
fn all_statuses_and_descriptors_must_confirm_exact_bytes() {
    for status in [200, 202, 204, 301, 307, 400, 500] {
        let http = Fixed(Response {
            status,
            headers: BTreeMap::new(),
            body: b"preserved failure".to_vec(),
        });
        let uploader = Uploader::new(&http, "https://upload.test/", 128, None, false).unwrap();
        assert_eq!(
            block_on(uploader.upload(b"abc")).unwrap_err(),
            UploadError::Http {
                status,
                body: b"preserved failure".to_vec()
            }
        );
    }
    for body in [
        json!({"ref":"x","size":3,"sha256":"a".repeat(64)}),
        json!({"ref":"x","size":4,"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}),
        json!({"ref":"x","size":3}),
    ] {
        let http = Fixed(Response {
            status: 201,
            headers: BTreeMap::from([("content-type".into(), "application/json".into())]),
            body: serde_json::to_vec(&body).unwrap(),
        });
        let uploader = Uploader::new(&http, "https://upload.test/", 128, None, false).unwrap();
        assert_eq!(
            block_on(uploader.upload(b"abc")).unwrap_err(),
            UploadError::Descriptor
        );
    }
}
#[test]
fn limits_and_destination_are_explicit() {
    let local = local();
    for endpoint in [
        "http://upload.test/",
        "https://secret@upload.test/",
        "https://upload.test/#fragment",
        "file:///tmp/raw",
    ] {
        assert!(Uploader::new(&local, endpoint, 128, None, false).is_err());
    }
    assert!(Uploader::new(&local, "http://127.0.0.1:8888/", 128, None, true).is_ok());
    assert!(Uploader::new(&local, "http://127.0.0.1:8888/", 128, None, false).is_err());
    let uploader = Uploader::new(
        &local,
        "https://uploads.test/raw?purpose=hook",
        2,
        Some(UploadCredential::bearer("upload-a").unwrap()),
        false,
    )
    .unwrap();
    assert_eq!(
        block_on(uploader.upload(b"abc")).unwrap_err(),
        UploadError::TooLarge
    );
}
#[test]
fn zero_byte_upload_and_entry_bound() {
    let local = local();
    let uploader = Uploader::new(
        &local,
        "https://uploads.test/raw?purpose=hook",
        128,
        Some(UploadCredential::bearer("upload-a").unwrap()),
        false,
    )
    .unwrap();
    for _ in 0..4 {
        assert!(block_on(uploader.upload(b"")).is_ok());
    }
    assert!(matches!(
        block_on(uploader.upload(b"")),
        Err(UploadError::Http { status: 413, .. })
    ));
}

#[test]
fn invalid_framing_never_allocates_or_publishes_a_reference() {
    let local = local();
    let request = Request {
        method: "POST".into(),
        uri: "https://uploads.test/raw?purpose=hook".into(),
        headers: BTreeMap::from([
            ("authorization".into(), "Bearer upload-a".into()),
            ("content-type".into(), "application/octet-stream".into()),
            ("content-length".into(), "3".into()),
            (
                "ahp-content-sha256".into(),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
            ),
        ]),
        body: b"abc".to_vec(),
    };
    for (name, value) in [
        ("content-length", "2"),
        ("ahp-content-sha256", "invalid"),
        ("content-encoding", "gzip"),
        ("transfer-encoding", "chunked"),
        ("Content-Length", "3"),
        ("content-type", "application/json"),
    ] {
        let mut bad = request.clone();
        bad.headers.insert(name.into(), value.into());
        assert_eq!(local.0.lock().unwrap().handle(bad).status, 400, "{name}");
    }
    let response = local.0.lock().unwrap().handle(request);
    assert_eq!(response.status, 201);
    let reference: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(reference["ref"], "content-1");
}

#[test]
fn canonical_descriptor_constraints_and_integral_number_presence() {
    let hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    for body in [
        json!({"ref":"","size":3,"sha256":hash}),
        json!({"ref":"x","size":3,"sha256":hash,"secret":"forbidden"}),
    ] {
        let http = Fixed(Response {
            status: 201,
            headers: BTreeMap::from([("content-type".into(), "application/json".into())]),
            body: serde_json::to_vec(&body).unwrap(),
        });
        let uploader = Uploader::new(&http, "https://upload.test/", 128, None, false).unwrap();
        assert_eq!(
            block_on(uploader.upload(b"abc")).unwrap_err(),
            UploadError::Descriptor
        );
    }
    let http = Fixed(Response {
        status: 201,
        headers: BTreeMap::from([("content-type".into(), "application/json".into())]),
        body: format!(r#"{{"ref":"x","size":3.0,"sha256":"{hash}"}}"#).into_bytes(),
    });
    let uploader = Uploader::new(&http, "https://upload.test/", 128, None, false).unwrap();
    let reference = block_on(uploader.upload(b"abc")).unwrap();
    assert_eq!(reference.size.as_number().to_string(), "3.0");
}
