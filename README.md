# certmatch

Verifies that a certificate file and a private key file actually belong
together (their public keys match) and that a certificate chain file is
correctly ordered (leaf → intermediate → root, each cert's issuer
matching the next cert's subject) — catches the classic "wrong key
deployed with this cert" nginx/deploy footgun, and the "chain file has
the intermediate and leaf swapped" mistake, both usually only discovered
after a real TLS handshake starts failing in production.

## Usage

```bash
certmatch check-pair server.crt server.key
certmatch check-chain fullchain.pem
```

Exit code `1` on a mismatch or a broken chain.

## How it works

Rather than reimplementing X.509/PKCS8 parsing, this shells out to the
real `openssl` binary — the same tool anyone debugging this by hand
already reaches for — and compares its output: `openssl x509 -pubkey`
against `openssl pkey -pubout` for the pair check (identical
`SubjectPublicKeyInfo` PEM output means the same key), and
`openssl x509 -subject`/`-issuer` for each certificate in a chain file,
checking that each one's issuer matches the next one's subject.

## Status: built and verified against real openssl-generated certificates and a real 3-tier CA chain — including two real bugs this OpenSSL build's own quirks caused

- **10 unit tests** (`cargo test --lib`): PEM comparison tolerating
  different line-wrapping/line-ending styles while still catching a
  genuinely different key; splitting a multi-certificate PEM bundle
  (two certs, one cert, empty input); chain-order validation (correct
  order, a broken link reporting the right index, a single-certificate
  chain and an empty chain both trivially valid).
- **A real bug caught live**: on this machine's actual OpenSSL 3.6.4,
  `openssl pkey -noout -pubout` silently produces **no output at all**
  (exit 0, empty stdout, empty stderr) — `-noout` and `-pubout` don't
  compose for the `pkey` subcommand the way they do for `x509`. This
  was only caught because a *genuinely matching* real cert/key pair
  (generated fresh with `openssl req -x509 -newkey rsa:2048`) was
  reported as a mismatch — the key's "public key" was just empty text.
  Fixed by dropping `-noout` from that one invocation.
- **A second real bug caught live, in the same debugging pass**:
  `openssl x509 -subject -nameopt oneline` prints `subject=CN = ...`
  with the label built in — the code was comparing these labeled
  strings directly against `issuer=CN = ...`, so a *correctly* ordered
  chain could never match (the labels themselves always differ). Fixed
  by stripping the `subject=`/`issuer=` prefix before comparing.
- **Live-verified after both fixes, against a real 3-tier CA chain**:
  built a real root CA, a real intermediate CA actually signed by that
  root (`openssl x509 -req -CA root_cert.pem -CAkey root_key.pem`), and
  a real leaf cert actually signed by that intermediate — three
  genuinely chained real certificates, not fixtures. `check-pair`
  correctly reported `MATCH` for a real matching cert/key pair and
  `MISMATCH` for a real mismatched one. `check-chain` correctly reported
  `OK` for the real chain in the right order (leaf, then intermediate)
  and correctly reported `BROKEN at position 0` when the same two real
  certificates were concatenated in the wrong order.

**Not done / deliberately deferred**: full chain-of-trust verification
(signature validation, expiry checking, whether the root is actually
trusted) — this only checks subject/issuer name matching for ordering,
the same limited scope a quick manual `openssl x509 -subject -issuer`
comparison has; a real `openssl verify` call is a different, heavier
check this tool doesn't attempt. Requires a real `openssl` binary on
`PATH` — there's no pure-Rust fallback.
