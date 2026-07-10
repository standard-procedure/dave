# SMB3 Dialect & Encryption — Design / Staging Plan

Tracks GitHub issue **#3** (SMB3: add 3.x dialect negotiation and transport
encryption). This is a design + decomposition doc; each stage below becomes its
own issue/PR. Builds on **#2** (message signing), which introduced the NTLMv2
`ExportedSessionKey` — the SMB2 `SessionKey` that every SMB3 key derives from.

## Current state

`samba-dave` negotiates **only SMB 2.0.2 / 2.1**:

- `negotiate.rb` selects `SMB2_1` or `SMB2_0_2` and never offers 3.x.
- The 3.x dialect *codes* exist (`Dialects::SMB3_0 = 0x0300`, `SMB3_0_2 = 0x0302`,
  `SMB3_1_1 = 0x0311`) but nothing else does — no capabilities, negotiate
  contexts, cipher constants, KDF, CMAC, or Transform-header handling.
- Signing (from #2) is HMAC-SHA256 with `SigningKey == SessionKey` — correct for
  2.x, but 3.x uses a different key derivation *and* a different MAC.

## What SMB3 actually requires (authoritative)

From MS-SMB2 and Microsoft's "SMB 2 and SMB 3 security in Windows 10: the anatomy
of signing and cryptographic keys" (the source of the KAT vectors below).

| Dialect | Key derivation | Signing | Encryption |
|---------|----------------|---------|------------|
| 2.0.2 / 2.1 | `SigningKey = SessionKey` (no KDF) | HMAC-SHA256 | — |
| 3.0 / 3.0.2 | SP800-108 KDF | **AES-128-CMAC** | **AES-128-CCM** |
| 3.1.1 | SP800-108 KDF, context = preauth hash | AES-128-CMAC | AES-128-CCM **and AES-128-GCM** |

### SP800-108 KDF ("SMB3KDF")

Counter Mode (SP800-108 §5.1), `r = 32`, `L = 128`, **HMAC-SHA256** as the PRF.
`Ki` = the 16-byte `SessionKey`; output `Ko` = leftmost 128 bits.

```
Ko = KDF-Counter(Ki = SessionKey, Label, Context)
  # single iteration (L=128 ≤ HMAC-SHA256 output): 
  # PRF( Ki, [i=1]_32 || Label || 0x00 || Context || [L=128]_32 )[0,16]
```

Labels/contexts (NUL-terminated ASCII):

**3.0 / 3.0.2** (context is a fixed string):
- `SigningKey    = KDF(SessionKey, "SMB2AESCMAC\0", "SmbSign\0")`
- `EncryptionKey = KDF(SessionKey, "SMB2AESCCM\0",  "ServerOut\0")`  ← server encrypts with this
- `DecryptionKey = KDF(SessionKey, "SMB2AESCCM\0",  "ServerIn \0")`  ← server decrypts with this (note trailing space)

**3.1.1** (context = `Session.PreauthIntegrityHashValue`):
- `SigningKey    = KDF(SessionKey, "SMBSigningKey\0",   PreauthHash)`
- `EncryptionKey = KDF(SessionKey, "SMBS2CCipherKey\0", PreauthHash)`  ← server→client
- `DecryptionKey = KDF(SessionKey, "SMBC2SCipherKey\0", PreauthHash)`  ← client→server

### Known-answer vectors (for KAT tests)

From the Microsoft walkthrough — lets us verify the KDF byte-for-byte without a
live client, exactly as #2 did for the NTLMv2 session key.

```
# SMB 3.0
SessionKey 7CD451825D0450D235424E44BA6E78CC
  → SigningKey    0B7E9C5CAC36C0F6EA9AB275298CEDCE
  → EncryptionKey FAD27796665B313EBB578F388632B4F7
  → DecryptionKey B0F0427F7CEB416D1D9DCC0CD4F99447

# SMB 3.1.1 (context = preauthIntegrityHashValue 0DD13628…3C6C01)
SessionKey 270E1BA896585EEB7AF3472D3B4C75A7
  → SigningKey    73FE7A9A77BEF0BDE49C650D8CCB5F76
  → EncryptionKey 629BCBC54422A0F572B97F45989B6073
  → DecryptionKey E2AF0DCEFAC68DA71A0DFBD0D1350D74
```

### Crypto primitive availability (Ruby 4.0 / OpenSSL 3.6, verified)

- **AES-128-GCM**: available (`OpenSSL::Cipher`).
- **AES-128-CCM**: available (`OpenSSL::Cipher`; watch Ruby's CCM nonce/tag API quirks).
- **AES-128-CMAC**: **NOT available** — no `OpenSSL::CMAC`/`OpenSSL::MAC` in this
  build. Implement RFC 4493 in pure Ruby over OpenSSL's `aes-128-ecb` single
  block (same approach as the pure-Ruby RC4 in #2). ~40 lines, KAT-testable
  against RFC 4493 vectors.

## Staging

Dependency-ordered; each stage is a shippable PR. A modern macOS/iOS client may
refuse to negotiate below 3.1.1, so **3a/3b are foundational steps that only
fully pay off for such clients once 3c lands** — but they establish the KDF,
CMAC, dialect plumbing, and Transform-header machinery that 3.1.1 reuses, and
they are independently testable (and unblock 3.0-capable Windows clients).

### Stage 3a — SMB 3.0 / 3.0.2 negotiation + signing

**Goal:** a 3.0/3.0.2 client negotiates, authenticates, and exchanges
AES-CMAC-signed traffic.

- **Dialect negotiation** (`negotiate.rb`): offer/select 3.0 and 3.0.2; set the
  appropriate `Capabilities` and `SecurityMode`. Keep 2.x working.
- **Track the negotiated dialect** on the connection (set in `handle_negotiate`)
  so signing-key derivation and MAC selection know which dialect is in force.
- **SP800-108 KDF** — new `SambaDave::Crypto::SP800108` (or `NTLM`-sibling
  module). KAT against the SMB 3.0 vector above.
- **Pure-Ruby AES-128-CMAC** — `SambaDave::Crypto::CMAC` (RFC 4493). KAT against
  RFC 4493 test vectors.
- **Dialect-aware signing** — `Session#set_session_key` takes the dialect and
  derives the right signing key (2.x → raw `SessionKey`; 3.0/3.0.2 → KDF).
  `MessageSigner` gains algorithm selection: HMAC-SHA256 (2.x) vs AES-CMAC (3.x),
  either via a `signing_algorithm` the session carries or an explicit arg. The
  connection's sign/verify call sites stay dialect-agnostic.
- **Sign the final SESSION_SETUP response** for 3.x (already done generically in
  #2; verify it holds under CMAC).

**Acceptance:** NEGOTIATE offers/selects 3.0/3.0.2; SMB3 signing-key KDF +
AES-CMAC in place and KAT-verified; a 3.0 handshake round-trips with valid CMAC
signatures; 2.x signing unchanged. **No encryption yet.**

### Stage 3b — AES-128-CCM transport encryption (3.0 / 3.0.2)

**Goal:** encrypted round-trips for 3.0/3.0.2.

- **Transform header** (`SMB2_TRANSFORM_HEADER`, 52 bytes: `0xFD 'SMB'`,
  Signature[16], Nonce[16], OriginalMessageSize[4], Reserved[2],
  Flags/EncryptionAlgorithm[2], SessionId[8]).
- **Encryption/Decryption keys** via the 3.0 KDF labels above.
- **AES-128-CCM**: 11-byte nonce, 16-byte auth tag; AAD = Transform header from
  Nonce onward (i.e. header minus the Signature field).
- **Connection**: detect Transform-wrapped inbound (`0xFD 'SMB'`), decrypt →
  dispatch the plaintext SMB2 message; encrypt outbound when the session/share
  requires it. Honour `SMB2_SESSION_FLAG_ENCRYPT_DATA` and per-share encryption.

**Acceptance:** encrypted round-trip works against a 3.0 client that requires
encryption; unencrypted still works when not required.

### Stage 3c — SMB 3.1.1 + AES-128-GCM

**Goal:** what modern Windows/macOS/iOS actually negotiate.

- **Negotiate contexts** in NEGOTIATE request/response:
  `SMB2_PREAUTH_INTEGRITY_CAPABILITIES` (hash alg SHA-512 + 32-byte salt) and
  `SMB2_ENCRYPTION_CAPABILITIES` (cipher IDs `0x0002` AES-128-GCM, `0x0001`
  AES-128-CCM).
- **Pre-auth integrity**: maintain a running SHA-512 hash over the NEGOTIATE and
  SESSION_SETUP messages; the final value is the KDF context for 3.1.1 keys.
- **3.1.1 KDF** — same SP800-108, preauth-hash context, new labels. KAT against
  the SMB 3.1.1 vector above.
- **AES-128-GCM**: 12-byte nonce, 16-byte tag; Transform header
  EncryptionAlgorithm/Flags = GCM.

**Acceptance:** a 3.1.1 client requiring encryption mounts and transfers files;
preauth-integrity handshake correct; KAT-verified 3.1.1 keys.

## Testing strategy

- **KAT the KDF** (3.0 and 3.1.1) and **CMAC** (RFC 4493) as pure unit tests —
  gold-standard confidence without a live client, matching #2's approach.
- **Connection-level integration** per stage: a 3.0 signed round-trip (3a); an
  encrypted round-trip (3b); a 3.1.1 preauth + encrypted handshake (3c) — driving
  the real handshake and verifying real MACs/ciphertext on the wire, deriving the
  client-side keys via the server's own KDF (no re-implementation in tests).
- **Real-client smoke test** (manual, per stage): mount from a client configured
  to require the target dialect + encryption.

## Out of scope (separate issues if wanted)

Multichannel / session binding; SMB Direct (RDMA); compression; leasing/oplocks;
directory-change encryption edge cases.
