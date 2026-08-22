# Shelf Oracle

**Single-server computational private information retrieval, RLWE-based, in the browser.**

Live demo: **https://systemslibrarian.github.io/crypto-lab-shelf-oracle/**

---

## What It Is

A library catalog can answer *which book do you want?* only by learning the answer. **Private information retrieval (PIR)** breaks that rule: you get the record you asked for, and the server never learns which one it was.

The classic way needs **two** servers that never talk to each other. This lab does it with **one**.

**The construction.** Single-server computational PIR in the style of **SealPIR** — Sebastian Angel, Hao Chen, Kim Laine and Srinath Setty, *PIR with Compressed Queries and Amortized Query Processing*, IEEE Symposium on Security and Privacy, 2018 — reduced to its direct one-hot form:

1. The client encrypts a **selection vector** `b` of length `N` under BFV: `b[index] = 1`, every other entry `0`.
2. The server computes `Σᵢ Rᵢ · Enc(bᵢ)` over its own plaintext records — one **plaintext-by-ciphertext multiplication** per record, then homomorphic addition.
3. Every term with `bᵢ = 0` contributes the zero polynomial. The single term with `bᵢ = 1` contributes `R_index`. So the sum **is** the record, and one ciphertext comes back.

**The encryption** is BFV — Junfeng Fan and Frederik Vercauteren, *Somewhat Practical Fully Homomorphic Encryption*, IACR ePrint 2012/144 — hand-rolled here over `R_q = Z_q[X] / (X^n + 1)`. Key generation, encryption, decryption, plaintext multiplication and ciphertext addition. **No ciphertext-by-ciphertext multiplication**, and therefore no relinearization: the one-hot form never needs one, which is precisely why it fits in a 2²⁶ modulus at all.

**The security model.** `Enc(0)` and `Enc(1)` are indistinguishable without the secret key under the **decision-RLWE** assumption, so the query carries no index that a computationally bounded adversary can extract. That word — *computational* — is the entire difference from [Oblivious Shelf](https://systemslibrarian.github.io/crypto-lab-oblivious-shelf/) and [Patron Shield](https://systemslibrarian.github.io/crypto-lab-patron-shield/), which are information-theoretic and pay for it with a second server that must never collude. Removing the collusion assumption is possible, and this lab is about what removing it costs.

**The parameters.** `n = 1024`, `q` prime just under 2²⁶, `t = 17`, uniform ternary secret, centred-binomial error with `η = 21` (`σ = √10.5 ≈ 3.24`). That `(n, log q, ternary, σ)` tuple sits inside the **128-bit classical** row of the *Homomorphic Encryption Security Standard* (HomomorphicEncryption.org, November 2018), whose ceiling for `n = 1024` is `log q ≤ 27`. The page prints that assessment, and raising `q` to 2³⁰ makes it print `PARAM_UNSAFE` instead.

**Not production cryptography.** A row of a 2018 table is an estimate, not a proof, and it says nothing about this implementation: the polynomial arithmetic is schoolbook `O(n²)` rather than an NTT, nothing is constant time, the server's inner loop skips zero plaintext coefficients so its running time depends on its own data, the secret key sits in ordinary browser memory, and none of it has been audited. Both "servers" are objects in one page; no network is involved. What **is** real is the mathematics — every ciphertext, every homomorphic multiply, every noise measurement, every byte count and every timing on the page is computed or measured, never scripted.

---

## Exhibits

1. **The Shelf** — 64 public-domain works with real authors, dates and Library of Congress class letters. Pick one; that choice is the only secret in the protocol. Shows the exact 512-byte record a successful query returns, its SHA-256 integrity tag, and — behind a disclosure — the byte-to-coefficient packing, four bits at a time, taken from the record actually on screen. Also carries the **run seed**: pin one and the whole run becomes reproducible, including the secret key, with the warning that deserves.

2. **The Server's View** — the plaintext selection vector greyed out as *what never leaves your machine*, beside 64 opaque ciphertexts as *what the server gets*. Guess which one encrypts the `1`. Then a real distinguisher runs 40 trials and reports its measured accuracy against the 1-in-16 baseline — and a single clearly-marked switch reuses one random pair across every entry, at which point the same crude attack is right **every time**. Nothing about the attack changes; only the encryption does.

3. **Homomorphic Selection** — the headline mechanism, stepped. Fold one record, eight, or the rest, and watch all 64 light up as the server multiplies them in: it cannot see which bit is the `1`, so it has no choice but to do the work for every record. The **noise budget falls, measured** — the running ciphertext is decrypted and compared against what it ought to hold — beside the six-sigma prediction derived from the parameters alone. Until the chosen record is folded in, the accumulator decrypts to literal zero. At the end, one decryption produces a record the server never identified.

4. **One Server vs Two** — both protocols run over the identical shelf, with upload and download taken by serializing and milliseconds taken by timing. Two servers win every row that is a cost: cheaper, faster, exact. They lose exactly two, and the two are the same fact said twice — this scheme needs one server, so there is no non-collusion assumption to make. One red button spends the assumption they rest on — XOR the two masks and the index falls out in a single operation, with no cryptanalysis and no time. There is no equivalent button for the single-server column, and that is the trade.

5. **Noise Exhaustion** — three knobs that all move real arithmetic: ciphertext modulus, record size, shelf length. Push until the budget reaches zero and the answer decrypts to garbage, reported through the record's own integrity tag and a count of coefficients outside the encodable range. Includes the parameter assessment against the published table, and a failure-code lab where each of the four codes is raised by a real input.

6. **What It Does Not Hide** — the negative claim, shown. Run queries and watch an observer's log fill with rows identical in **size** and different in **time**: fixed response length is a property of this construction, and occurrence, timing, frequency and identity are not. A table separates what the protocol hides from what a deployment would have to, and links forward to [Search Vault](https://systemslibrarian.github.io/crypto-lab-search-vault/) and [ORAM Vault](https://systemslibrarian.github.io/crypto-lab-oram-vault/).

---

## When to Use It

**Use single-server computational PIR when you cannot get non-collusion.** Two-server PIR is cheaper on every metric this lab measures, but it needs two operators under genuinely separate control — separate staff, separate jurisdictions, separate subpoena exposure. That is an organisational problem, not a technical one, and it is the reason single-server constructions get built at all.

**Use it when the query index is the sensitive thing** and the database is small enough, or the deployment rich enough, to pay `O(N)` server work per query. Every PIR scheme touches the whole database; there is no way around it, because skipping a record would prove it was not the answer.

**Do NOT use it as an access-control mechanism.** Nothing checks that your selection vector is one-hot, and nothing can — the server cannot read it. A client that sends two ones gets the sum of two records back. PIR bounds what the *server* learns, not what the *client* extracts.

**Do NOT use it where the leak is the pattern rather than the index.** PIR hides one query. Hiding a *sequence* of accesses is oblivious RAM's problem — see ORAM Vault.

**Do NOT use this code.** It is a teaching implementation. Real deployments use SEAL, OpenFHE or Lattigo.

---

## Live Demo

**https://systemslibrarian.github.io/crypto-lab-shelf-oracle/**

You can: pick any of 64 books; watch the encrypted selection vector be built and try to distinguish `Enc(1)` from `Enc(0)` yourself; break the encryption's randomness and watch a distinguisher go from chance to certain; step the homomorphic inner product record by record with a live measured noise budget; run single-server and two-server PIR head to head with real byte counts; make the two servers collude and recover the index instantly; shrink the modulus until decryption returns garbage; trip all four failure codes; and watch what a network observer still sees after all of it.

---

## What Can Go Wrong

The threat model, and the four named failure codes.

**Who the adversary is.** An *honest-but-curious* server that follows the protocol and tries to learn the index from what it receives, plus a *passive network observer* that sees traffic but no plaintext. Privacy against the server is **computational**, resting on decision-RLWE at the parameters in use.

**What breaks it.**

- **`NOISE_BUDGET_EXHAUSTED`** — every record folded into the answer contributes its own encryption error, including the ones multiplied by an encrypted zero. Past the ceiling the answer still decrypts; it decrypts to garbage. The page detects it three ways, and reports them separately because only two are things a real client could do: the record's own SHA-256 tag fails, coefficients come back outside `[0, 16)` where the encoder can never put them, and — using the secret key and the true record, which a real client has neither of — the measured budget reaches zero. **A deployment sizes its parameters in advance; it does not discover exhaustion at runtime.**
- **`PARAM_UNSAFE`** — the `(n, log q)` pair has left the published 128-bit table, or would push this implementation past 2⁵³ where JavaScript integers stop being exact. The second is the more insidious: past that bound nothing throws and no coefficient looks wrong, so the demo would go on producing plausible garbage while claiming exactness.
- **`DIM_MISMATCH`** — the query is not the same length as the shelf. Refused **before any homomorphic work**, because a short query answers over a prefix and a long one reads past the end, and both return a ciphertext that decrypts to something.
- **`INDEX_OUT_OF_RANGE`** — the requested shelf position does not exist.

**What the protocol does not defend against.**

- **A malicious server.** PIR provides no integrity. A server that wants to lie can return a different record with a matching tag; the tag is part of the record it holds. Verifiable PIR is a separate line of work.
- **Traffic metadata.** Occurrence, timing, frequency, count, client identity and database size all leak. What does *not* leak is the index: the response is one ciphertext of the same size whichever record you asked for, and the query is one ciphertext per shelf position whichever position it is. Those lengths are perfectly visible — they announce the shelf size — they simply do not vary with the answer, and that is by construction rather than by padding. Padding and traffic shaping are separate mechanisms for the things that do leak; PIR does not claim them.
- **Access patterns over many queries.** Each query is individually private. Hiding the sequence is ORAM's job.
- **A malformed client query.** Unauthenticated by construction — see *When to Use It*.
- **Side channels.** Nothing here is constant time. The server's inner loop skips zero plaintext coefficients, so its running time depends on its own data; that costs nothing in this demo because the shelf is public, and it is exactly the shortcut a deployment must not take.

---

## Real-World Usage

Single-server PIR is a live research and deployment area, not a museum piece.

- **SealPIR** (Angel–Chen–Laine–Setty, IEEE S&P 2018) introduced **query expansion**: the client sends one ciphertext plus Galois keys and the server expands it into the full selection vector with plaintext substitutions, turning an upload linear in the database into a constant one. That is the single largest engineering difference between this page and the paper, and this lab does not do it — the head-to-head exhibit says so rather than quietly reporting SealPIR's numbers.
- **OnionPIR** and the **Spiral** family push the same line further with better rate and smaller responses.
- **Two-server, information-theoretic PIR** (Chor–Goldreich–Kushilevitz–Sudan, FOCS 1995) remains active and practical; it is not obsolete, it simply buys its unconditional privacy with a non-collusion assumption. This lab implements it too, so the comparison can be measured rather than asserted.
- The underlying homomorphic encryption is deployed at scale — Microsoft SEAL, OpenFHE, Lattigo — in private set intersection, encrypted database queries and privacy-preserving telemetry.
- The library-privacy framing is not decorative. What patrons read is sensitive metadata, and the profession has defended it for a long time; PIR is one of the few mechanisms that lets a catalog answer a question it is not allowed to remember.

---

## How to Run Locally

```bash
npm install
npm run dev          # http://localhost:5173/crypto-lab-shelf-oracle/

npm test             # the cryptographic unit suite
npm run build        # tsc --noEmit && vite build
npm run test:a11y    # the browser gate: axe WCAG A/AA + the claims suite
```

The browser gate builds first and serves the production bundle, so what passes is what ships. Playwright's Chromium is installed with `npx playwright install chromium` — never `--with-deps`.

---

## Related Demos

- **[Oblivious Shelf](https://systemslibrarian.github.io/crypto-lab-oblivious-shelf/)** — two-server XOR IT-PIR (Chor et al. 1995) over a 16-entry shelf, step by step. The other half of this lab's trade.
- **[Patron Shield](https://systemslibrarian.github.io/crypto-lab-patron-shield/)** — the same two-server scheme framed as library ethics, with a one-click collusion attack.
- **[FHE Arena](https://systemslibrarian.github.io/crypto-lab-fhe-arena/)** — BGV/BFV with ciphertext-by-ciphertext multiplication, relinearization and the noise budget this lab borrows and puts to work.
- **[Search Vault](https://systemslibrarian.github.io/crypto-lab-search-vault/)** — searchable encryption that deliberately leaks the access pattern, then inverts it with the count and IKK attacks. What happens when the leakage this lab refuses to produce is produced.
- **[ORAM Vault](https://systemslibrarian.github.io/crypto-lab-oram-vault/)** — Path ORAM hides the *sequence* of locations touched, the row this lab's table marks as not hidden.

---

## Build & Verify

**87 unit tests** across five files, all passing (`npm test`).

**Spec known-answer tests.** Two published sources anchor this lab; both are quoted, not generated by this implementation:

- **RFC 8439** (*ChaCha20 and Poly1305 for IETF Protocols*) — the §2.3.2 block-function vector and the §2.4.2 encryption vector, in `src/pir/chacha20.test.ts`. ChaCha20 is the sampler every ciphertext on the page is drawn from, so this is the anchor under the randomness layer.
- **The Homomorphic Encryption Security Standard** (HomomorphicEncryption.org, November 2018) — all **18 published ceilings** of the uniform-ternary classical table (`n ∈ {1024 … 32768}` × `{128, 192, 256}`-bit), checked one row at a time in `src/pir/records.test.ts`. That table is what `PARAM_UNSAFE` is decided against.

BFV and SealPIR publish no test vectors, so the rest of the suite is property-based rather than pretending otherwise, and the strongest check is a **three-way cross-scheme agreement**: single-server RLWE PIR, two-server XOR PIR and a plain array read must return the identical bytes. Two protocols with nothing in common plus a direct lookup — a bug in either protocol would have to be reproduced identically by the other to survive it.

Also covered: the negacyclic property checked directly (`X^(n-1) · X = -1`, not `+1` — a cyclic ring round-trips perfectly and no correctness test would notice); schoolbook multiplication against a definitional oracle; BFV round-trips over every plaintext value; additive homomorphism; that reused randomness makes `Enc(1) − Enc(0)` exactly `Δ`; that the server function has no argument through which the index could reach it; that the stepped fold reaches the same ciphertext as the one-shot server; that a partial answer decrypts to zero until the chosen record is folded in; that the measured budget falls monotonically; that the six-sigma prediction is a bound the measurement respects; UTF-8 truncation that never splits a sequence; wire-format round-trips at every modulus; and every failure code, raised and named.

**The browser gate** (`npm run test:a11y`) runs two suites against the production build:

- **`e2e/a11y.spec.ts`** — zero WCAG 2.1 A/AA violations, at 1280px and again at 380px, across roughly forty driven states. It is not an axe wrapper: it asserts axe's `incomplete` bucket as well as `violations` (which is where `aria-prohibited-attr` and every `color-mix()` contrast decision live), computes contrast arithmetically over composited backdrops, measures non-text contrast per border side against a ratchet baseline that is currently **empty**, and adds reflow, scroller-reachability and invisible-focus-target oracles that axe has no rules for. Reduced motion is set through `emulateMedia` and asserted from inside the page; nothing is injected and no panel is revealed from script.
- **`e2e/claims.spec.ts`** — 27 tests that check the page tells the truth, by comparing values the page itself printed rather than hardcoded strings: the record the fold returns against the record the shelf shows; the budget ceiling re-derived as `log2(⌊q/t⌋)` from the printed ring parameters; the query size re-derived from `n` and `log q` where the source measures a serialized buffer; the head-to-head upload against the Server's View figure; each failure code naming its actual cause with numbers that match the controls on screen; verdict **retirement** (change a parameter and the stale measurement is gone *and the page says why*, with the reason updating on the second change as well as the first) alongside a **no-op guard** (re-selecting the same book retires nothing); the `[hidden]` cascade probe; and that the page does not fight its reader — focus stays on the control you activated across the rebuild, the live region is one node that survives every render, and a demonstration failure code does not overwrite a real retrieval verdict.

**Defects found by the gate and by an adversarial review pass, and fixed rather than baselined:** `.panel { display: grid }` outranking the UA's `[hidden]` rule, which left five tabpanels in the tab order painting nothing; a missing `box-sizing: border-box` plus the grid `min-width: auto` default, which pushed the document sideways at 380px; `aria-label` on role-less tiles; keyboard focus being thrown to `<body>` on every re-render; live regions rebuilt inside a cleared subtree, so none of them could announce anything; a demonstration failure code overwriting a real retrieval verdict; a retirement reason latched on the first change; a hidden panel re-encrypting a 64-ciphertext query nobody was looking at; the comparison table conveying "better" by colour alone; and two rows of the what-is-hidden table contradicting each other about query length.

**Mutation-tested.** A green suite is not evidence until it has been watched failing. Eight mutations were applied one at a time — the negacyclic sign in the ring, the `DIM_MISMATCH` guard, fresh encryption randomness, the `[hidden]` rule, the no-op selection guard, focus restoration, live-region persistence, and the on-screen-panel re-render — each confirmed to compile, to change the bundle hash, to fail the test that owns it by name, and to restore to the identical hash.

---

## Performance

Measured in-page, on the reader's own machine, at the shipped defaults (`n = 1024`, `q ≈ 2²⁶`, 64 records of 512 bytes):

| | Shelf Oracle (1 server, RLWE) | Chor et al. XOR (2 servers) |
|---|---|---|
| Upload per query | ~416 KiB | 16 B |
| Download per query | ~6.5 KiB | 1 KiB |
| Client work | ~50 ms | ~0.1 ms |
| Server work | ~80 ms | ~0.6 ms |
| Records touched | 64 of 64 | ~half of 64, per server |
| Privacy | computational (RLWE) | information-theoretic |
| Trust assumption | none between operators | the two must never collude |

The upload column is the honest one and it is **not** SealPIR's: query expansion would make it constant rather than linear in the shelf, and sending the 32-byte seed that `c1` was expanded from instead of the polynomial would halve what remains. Both are out of scope here and named on the page. Timings are browser timings with a schoolbook `O(n²)` multiply where a real implementation uses an NTT — treat the ratio between columns as meaningful and the absolute values as anecdote.

Noise budget at those defaults: the ceiling is `log2(⌊q/t⌋) = 21.91` bits, a freshly encrypted record measures about **16.5** bits — encryption spends roughly five bits on its own sampled error before the server does anything — and the finished 64-record answer measures about **7.6**. At `q = 2¹⁸` the same query exhausts and the page says so through the record's own integrity tag.

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
