# Local TLS fixture

These certificates and the non-secret test server private key are used only by
the managed OAuth tests. The listener binds to a random loopback port; the host
network adapter pins oauth.test to that address, disables proxies and redirects,
and validates the server certificate with an explicit Rustls root store.
No production credential or private CA signing key is included.

The leaf certificate is valid from 2026-11-15 through 2036-11-12. Tests must renew
the fixture before expiry; they must never disable certificate or hostname checks.

## SDK lifecycle vectors

`sdk-auth-lifecycle.json` is an exact copy of the canonical protocol repository's
`conformance/draft/sdk-auth-lifecycle.json`, governed by
`spec/draft/sdk-auth-lifecycle.md`. Its SHA-256 is
`4b7f03758ebdba268d9ed218aa7c739c8a1207e9561c52e8f99b657a3eca2f97`.

Native tests consume the recovery, storage-key and token-response vectors. The
lifecycle entries are a coverage manifest, not executable runtime evidence;
managed HTTP/store and registration-transport tests exercise those lifecycles.
