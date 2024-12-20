# Kemeleon: Obfuscated ML-KEM Encodings

<p>
  <a href="https://crates.io/crates/kemeleon">
    <img src="https://img.shields.io/crates/v/kemeleon.svg" alt="kemeleon crates.io">
  </a>
  <a href="https://docs.rs/kemeleon">
    <img src="https://img.shields.io/docsrs/kemeleon" alt="kemeleon docs.rs">
  </a>
  <a href="https://github.com/jmwample/kemeleon/actions/workflows/rust.yml">
    <img src="https://github.com/jmwample/kemeleon/actions/workflows/rust.yml/badge.svg?branch=main" alt="Build Status">
  </a>
  <a href="https://codecov.io/gh/jmwample/kemeleon" >
    <img src="https://codecov.io/gh/jmwample/kemeleon/graph/badge.svg?token=0lMlrA32xd"/>
  </a>
  <a href="https://deps.rs/repo/github/jmwample/kemeleon">
    <img src="https://deps.rs/repo/github/jmwample/kemeleon/status.svg">
  </a>
  <a href="https://doc.rust-lang.org/1.6.0/complement-project-faq.html#why-dual-mitasl2-license">
    <img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue" alt="License: MIT/Apache 2.0">
  </a>
  <a href="https://github.com/jmwample/kemeleon#minimum-supported-rust-version-msrv">
    <img src="https://img.shields.io/badge/MSRV-1.81+-blue.svg" alt="MSRV 1.81">
  </a>
</p>

This crates implements the kemeleon algorithms for secure obfuscation of ML-KEM
Encapsulation Keys their corresponding Ciphertext responses which would otherwise
be trivially distinguishable from bytes sampled from a uniform random source.

The original algorithm designs and security proofs can be found in the
[_Obfuscated Key Exchange_](https://eprint.iacr.org/2024/1086.pdf)
paper written by _Felix Günther_ (IBM Research Europe – Zurich), _Douglas Stebila_ (University of Waterloo), _Shannon Veitch_ (ETH Zurich).

## ⚠️ Security Warning
<center>
The implementation contained in this crate has never been independently audited!

<h4><b>USE AT YOUR OWN RISK!</b></h4>
</center>


🚧  UNDER CONSTRUCTION  🚧
This library is in a devloping (non-stable) condition, meaning that things will likely change. This includes
API, interface, algorithms, etc. -- Feedback is welcome, but we do not guarantee support for any features /
interface as currently implemented.

## Usage

```rust
use kemeleon::{MlKem512, OKemCore, Encode};
use kem::{Encapsulate, Decapsulate};

type EncapKey<P> = <P as OKemCore>::EncapsulationKey;
type Ct<P> = <P as OKemCore>::Ciphertext;

let mut rng = rand::thread_rng();
let (dk, ek) = MlKem512::generate(&mut rng);

// Converting the Encapsulation key to bytes and back in order to be sent.
let ek_encoded: Vec<u8> = ek.as_bytes().to_vec();
let ek = EncapKey::<MlKem512>::try_from_bytes(&ek_encoded[..])
    .expect("failed to parse encapsulation key");

let (ct, k_send) = ek.encapsulate(&mut rng).unwrap();

// Converting the ciphertext to bytes and back in order to be sent.
let ct_bytes = ct.as_bytes();
let ct = Ct::<MlKem512>::try_from_bytes(&ct_bytes[..])
    .expect("failed to parse ciphertext");

let k_recv = dk.decapsulate(&ct).unwrap();
assert_eq!(k_send, k_recv);
```

## Why?

This library implements obfuscating encoding schemes for ML-KEM encapsulation
keys and ciphertext messages such that they are computationally indistinguishable
from random by a passive observer.

**Why aren't the NTT encodings from the FIPS spec (`ByteEncode_d(F)`, `ByteDecode_d(B)`, etc.) sufficient?**

The wire format of the encapsulation key is trivially distinguishable from uniform
random becuase they values are 12 bit values where all are computed mod Q. Thus
all values are 12 bits, but always less than 3329.

<div>
 <img style="display: block; margin-left: auto; margin-right: auto; width: 60%;" src="doc/kyber_rfc_dist.png" alt="ML-KEM768 byte Frequency">
</div>

## Minimum Supported Rust Version (MSRV)

The Minimum Supported Rust Versions (MSRV) for this crate is **Rust 1.81**
(currently forced by the [`hybrid-array`](https://docs.rs/hybrid-array) dependency).
This minumum version will be ensured by the test and build steps in the CI pipeline.

Going forward, the MSRV can be changed at any time, but it will be done with
a minor version bump. We will not increase MSRV on PATCH releases, though
downstream dependencies might.

Once this crate reaches a stable state we won't increase MSRV just because we
can: we'll only do so when we have a reason. (We don't guarantee that you'll agree
with our reasoning; only that it will exist.)

## Roadmap

### Core features

- [x] Public interface first pass
- [x] Interface with [`ml_kem`](https://docs.rs/ml-kem/latest)
- [x] Implement complete Encapsulation Key encoding / decoding
- [x] Implement and test ciphertext encoding / decoding
- [x] Pass on public docs
- [x] Switch from using `std::io::Error` to a locally defined error type.
- [x] Ciphertext encoding determinism using hkdf, hmac-drbg, or something similar
- [x] Modify implementation to be `no-std` compatible
  - [x] Swap from custom error to &str error just for simplicity (`core::error::Error` is too new)
- [x] GH actions for testing, building, linting, etc.
- [x] Use [`hybrid-array`](https://docs.rs/hybrid-array/0.2.0-rc.9/hybrid_array/) for
  all type based generics requiring sized arrays
  - [x] Move const generics (`#![feature(generics_const_exprs)]`) to its own branch
    - const generics are an unstable feature, even though this is a very simple
      application of the feature it is bad practice to ask people use it in its current state.
  - [x] CI tests/builds for stable releases (const generics only work on nightly)
- [x] ~Nist vectors Integration tests~

### Cleanup -> Release 0.1.0

- [ ] ([`RustCrypto/KEMs#81`](https://github.com/RustCrypto/KEMs/pull/81)) - Make `ml_kem::(En|De)capsulationKey` more usable.
- [ ] Polish public interface and docs
- [ ] Github actions release workflow
- [ ] Impl `OKemCore` for `xwing` and `DHKEM`
- [ ] Decide how to handle serializing and Deserializing `DecapsulationKey`s wrt. high order bits of the kemeleon encoded `EncapsulationKey`s

### Heading to Release 0.1.1

- [ ] work up PR(s) for [ml-kem](https://docs.rs/ml-kem/latest/ml_kem/)
- [ ] remove as much repeated functionality as possible
- [ ] revisit secure deterministic random byte generation
