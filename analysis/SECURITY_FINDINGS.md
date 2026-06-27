# Security Findings — RustFileEncryptor

**Audited:** `src/main.rs`, `Cargo.toml`, `Cargo.lock`
**Tool:** `cargo audit` + manual adversarial review
**Dependency advisories:** 0 (51 crates scanned, none flagged)
**Hardcoded credentials:** 0

---

## Summary Scorecard

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High     | 2 |
| Medium   | 3 |
| Low      | 2 |
| **Total**| **7** |

**Top CWE categories:** CWE-190 (Integer Overflow), CWE-400 (Resource Consumption), CWE-330/323 (Nonce Reuse), CWE-922/312 (Sensitive Data Exposure)

---

## Dependency CVE Table

| Package | Installed | CVE | Fixed Version |
|---------|-----------|-----|---------------|
| *(none)* | — | — | — |

`cargo audit` output:
```
Loaded 1139 security advisories
Scanning Cargo.lock for vulnerabilities (51 crate dependencies)
0 vulnerabilities found.
```

---

## Findings Table

| ID | Severity | CWE | Location | Summary |
|----|----------|-----|----------|---------|
| SEC-001 | **High** | CWE-190 | `src/main.rs:110,161` | Chunk counter cast `i as u32` silently wraps for files >256 TB, reusing a nonce and breaking AES-GCM |
| SEC-002 | **High** | CWE-400 | `src/main.rs:150,160` | Attacker-controlled chunk count in `.enc` header is never validated against actual file size, enabling infinite-loop DoS |
| SEC-003 | Medium | CWE-323 | `src/main.rs:35-40` | Nonce space is 2³²-1 chunks (~256 TiB) with no enforced cap; exceeding it reuses nonces |
| SEC-004 | Medium | CWE-922 | `src/main.rs:102,157` | Output file created before operation completes; crash/kill mid-run leaves partial plaintext on disk |
| SEC-005 | Medium | CWE-312 | `src/main.rs:54-65` | Password `String` not zeroed on drop; may remain readable in heap memory or core dumps |
| SEC-006 | Low | CWE-20 | `src/main.rs:228` | Input path not validated before use; empty/whitespace path produces confusing deep I/O errors |
| SEC-007 | Low | CWE-311 | `src/main.rs:19-21` | Argon2 KDF parameters not stored in file header; a crate-default change silently makes files undecryptable |

---

## Detailed Findings

### SEC-001 — Integer Overflow in Chunk Index Cast (High)
**CWE-190** · `src/main.rs:110` (encrypt), `src/main.rs:161` (decrypt)

`i as u32` truncates silently when `chunk_count > u32::MAX` (~4 billion chunks, i.e., files larger than 256 TB). Once the counter wraps back to 0, the nonce `[prefix || 0x00000000]` is reused for a second chunk, breaking AES-GCM's nonce-uniqueness requirement. Nonce reuse under GCM allows recovery of the XOR of two plaintexts and complete forgery of authentication tags.

**Fix:** Bound-check `chunk_count <= u32::MAX as u64` at both encryption and decryption entry points. Use `u32::try_from(i).unwrap()` in the loop so that any future regression is a panic rather than silent corruption.

---

### SEC-002 — Uncapped Chunk Count Enables DoS (High)
**CWE-400** · `src/main.rs:150,160`

During decryption, `chunk_count` is read verbatim from the first 32 bytes of the untrusted `.enc` file. A crafted file with `chunk_count = u64::MAX` (all `0xFF` bytes) causes the program to spin in a `for i in 0..u64::MAX` loop attempting `read_exact` calls until EOF, then hanging or burning CPU indefinitely. Any user who decrypts an untrusted file is vulnerable.

**Fix:** After reading `chunk_count`, compute `max_plausible = (actual_file_remaining_bytes) / (CHUNK_SIZE as u64 + 16) + 1` and reject the file if `chunk_count > max_plausible`.

---

### SEC-003 — Missing Enforcement of Nonce Space Limit (Medium)
**CWE-323** · `src/main.rs:35-40`

The 4-byte chunk index caps the nonce counter at 2³² − 1. No hard limit is enforced at encryption time, so a user encrypting a file larger than ~256 TiB will silently reuse nonces. SEC-001's fix (capping at `u32::MAX`) directly mitigates this as a side effect.

---

### SEC-004 — Partial Output File on Interrupted Operation (Medium)
**CWE-922** · `src/main.rs:102,157`

`File::create` is called before the operation succeeds. A kill signal, OOM, or disk-full error mid-run leaves a partial decrypted file with some original plaintext at the destination path. An atomic write pattern (write to temp file, rename on success, delete on failure) prevents this.

---

### SEC-005 — Password Not Zeroed After Use (Medium)
**CWE-312** · `src/main.rs:54-65`

`rpassword::prompt_password` returns a `String`. Rust's `Drop` for `String` deallocates but does not zero the heap buffer. The password bytes may persist in RAM until the allocator reuses that region, visible in `/proc/<pid>/mem`, core dumps, or swap. The `zeroize` crate (already transitively present via `aes-gcm`) provides a `Zeroizing<String>` wrapper that zeroes on drop.

---

### SEC-006 — No Input Path Validation (Low)
**CWE-20** · `src/main.rs:228`

`args[2]` is passed directly to the filesystem functions without checking that it is non-empty or is a valid file path. An empty string or pure-whitespace argument produces a deep `NotFound` I/O error rather than a clear usage message.

---

### SEC-007 — Argon2 Parameters Not Persisted (Low)
**CWE-311** · `src/main.rs:26`

`Argon2::default()` uses library-defined parameters. These are not stored in the `.enc` file header. If the `argon2` crate changes its defaults in a future version, existing files become silently undecryptable (key mismatch surfaces as "wrong password" with no further diagnostic). Storing the PHC string or explicit parameter bytes in the header enables forward compatibility and user-visible diagnostics.

---

## Remediation Log

| ID | Fix Summary | Patch file |
|----|-------------|-----------|
| SEC-001 | Reject `chunk_count > u32::MAX as u64`; replace `i as u32` with `u32::try_from(i).unwrap()` | `security_remediation.patch` |
| SEC-002 | After reading header, compute max plausible chunk count from file size and reject if exceeded | `security_remediation.patch` |
| SEC-003 | Mitigated as a side-effect of SEC-001 fix | `security_remediation.patch` |
| SEC-004 | (Medium — not in this patch; recommended future work: use `tempfile` crate) | — |
| SEC-005 | (Medium — not in this patch; recommended: wrap return of `prompt_password` in `Zeroizing<String>`) | — |
| SEC-006 | (Low — not in this patch) | — |
| SEC-007 | (Low — not in this patch) | — |

---

## Patch Review

Reviewed by security-auditor agent against the revised patch (v2, after one re-spin to tighten divisor and replace `expect` with `map_err`). No credentials in patch. All verdicts: **RESOLVES**.

| Hunk | Finding(s) | Verdict | Reason |
|------|-----------|---------|--------|
| A — encrypt cap | SEC-001, SEC-003 | RESOLVES | Pre-loop `u32::MAX` guard prevents nonce reuse; returns `Err` before any output is written |
| B — encrypt cast | SEC-001 | RESOLVES | `u32::try_from(i).map_err(...)?` replaces silent truncating cast; defence-in-depth |
| C — decrypt validation | SEC-002, SEC-001 | RESOLVES | Divisor `CHUNK_SIZE+16` (65552) gives tight plausibility bound; `u32::MAX` cap added as second guard |
| D — decrypt cast | SEC-001 | RESOLVES | Same safe-cast fix as Hunk B on the decrypt path |
