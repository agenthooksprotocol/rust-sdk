# Local TLS fixture

These certificates and the non-secret test server private key are used only by
the managed OAuth tests. The listener binds to a random loopback port; the host
network adapter pins oauth.test to that address, disables proxies and redirects,
and validates the server certificate with an explicit Rustls root store.
No production credential or private CA signing key is included.

The leaf certificate is valid from 2026-11-15 through 2036-11-12. Tests must renew
the fixture before expiry; they must never disable certificate or hostname checks.
