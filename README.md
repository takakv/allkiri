# allkiri

**Name-reservation stub.**
I intended this crate to be called `digidoc` but someone beat me to it while I was working on my own crate.
Incredibly frustrating.

## PKCS#11 / ID card

With the `pkcs11` feature, `allkiri` can sign an ASiC-E container using an Estonian ID card:

```sh
cargo run --features pkcs11 --example sign_id_card -- \
    test.txt test.asice
```

The issuer certificate is auto-discovered through the AIA CA Issuers.
Alternatively, fetch it manually with 

```sh
curl -O https://crt-test.eidpki.ee/testESTEID2025.crt
```

and pass the certificate as a third positional argument.

## License

Apache-2.0.
