# Test fixtures

Throwaway material generated with OpenSSL solely so the TLSA digests in the tests
can be asserted against values computed by an independent tool rather than by the
code under test.

- `leaf.crt` / `leaf.key` — a self-signed certificate and its RSA key. The key is
  needed to prove that record data derived from a private key alone matches the
  data derived from a certificate carrying that key, which is what makes
  pre-publication on renewal correct.
- `chain.crt` — a leaf followed by its issuing CA, used to check that the
  trust-anchor usages pick the issuer rather than the leaf.

**`leaf.key` is a private key committed on purpose.** It corresponds to nothing
real, guards nothing, and was generated for this test data. Do not reuse it.

Expected digests are recorded in `../tlsa_test.go`; regenerate them with, for
example:

```sh
openssl x509 -in leaf.crt -noout -pubkey | openssl pkey -pubin -outform DER | shasum -a 256
```
