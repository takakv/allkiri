# allkiri

**Name-reservation stub.**
I intended this crate to be called `digidoc` but someone beat me to it while I was working on my own crate.
Incredibly frustrating.

## PKCS#11 / ID card

With the `pkcs11` feature, `allkiri` can sign an ASiC-E container using an Estonian ID card:

```sh
cargo run --features pkcs11 --example sign_id_card -- \
    test.txt test.asice testESTEID2025.crt
```

Fetch the issuer certificate with

```sh
curl -O https://crt-test.eidpki.ee/testESTEID2025.crt
```

## License

Apache-2.0.
