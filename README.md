# Shelf Oracle

**Single-server computational private information retrieval, RLWE-based, in the browser.**

Live demo: **https://systemslibrarian.github.io/crypto-lab-shelf-oracle/**

---

## What It Is

A library catalog can answer *which book do you want?* only by learning the answer. **Private information retrieval (PIR)** breaks that rule: you get the record you asked for, and the server never learns which one it was.

The classic way needs **two** servers that never talk to each other. This lab does it with **one**.

**The construction.** Single-server computational PIR in the style of **SealPIR** — Sebastian Angel, Hao Chen, Kim Laine and Srinath Setty, *PIR with Compressed Queries and Amortized Query Processing*, IEEE Symposium on Security and Privacy, 2018. The mature baseline uses the direct one-hot form:

1. The client encrypts a **selection vector** `b` of length `N` under BFV: `b[index] = 1`, every other entry `0`.
2. The server computes `Σᵢ Rᵢ · Enc(bᵢ)` over its own plaintext records — one **plaintext-by-ciphertext multiplication** per record, then homomorphic addition.
3. Every term with `bᵢ = 0` contributes the zero polynomial. The single term with `bᵢ = 1` contributes `R_index`. So the sum **is** the record, and one ciphertext comes back.

The **Compressed Query** exhibit covers the same 64-record catalog with four fixed 16-selector blocks. The selected block encrypts `16⁻¹ · X^localIndex`; the other three encrypt zero. All four ciphertexts cross the wire, with no plaintext index or selected-block field; the choice is present only under encryption and hidden under the compressed path's stated assumptions. The server expands every block with the odd substitutions `X → X^1025`, `X^513`, `X^257` and `X^129`, noisy binary-gadget key switching, additions and negacyclic shifts; scans all 64 records; and returns four fixed ciphertexts. The client keeps the response for its private block. The direct decrypt, compressed decrypt and independently built catalog record must agree byte for byte and pass the record's SHA-256 decode tag; that tag detects decoding errors here, not a malicious server.

**The encryption** is BFV — Junfeng Fan and Frederik Vercauteren, *Somewhat Practical Fully Homomorphic Encryption*, IACR ePrint 2012/144 — hand-rolled here over `R_q = Z_q[X] / (X^n + 1)`. Key generation, encryption, decryption, plaintext multiplication and ciphertext addition remain the direct path. Expansion adds automorphisms and key switching, but still no ciphertext-by-ciphertext multiplication and therefore no relinearization. Dense switch-key products use two auxiliary NTT primes and exact CRT reconstruction with an executable coefficient bound; the record fold remains the readable schoolbook implementation.

**The security model.** On the direct path, `Enc(0)` and `Enc(1)` are indistinguishable without the secret key under the **decision-RLWE** assumption, so the query carries no index that a computationally bounded adversary can extract. The compressed path additionally publishes key-dependent Galois keys and therefore inherits the circular-security assumption stated below; ordinary IND-CPA alone does not cover that extra material. The word *computational* is the entire difference from [Oblivious Shelf](https://systemslibrarian.github.io/crypto-lab-oblivious-shelf/) and [Patron Shield](https://systemslibrarian.github.io/crypto-lab-patron-shield/), which are information-theoretic and pay for it with a second server that must never collude. Removing the collusion assumption is possible, and this lab is about what removing it costs.

**The parameters.** The mature direct exhibits default to `n = 1024`, `q` prime just under 2²⁶, `t = 17`, a uniform ternary secret and centred-binomial error with `η = 21` (`σ = √10.5 ≈ 3.24`). The compressed comparison fixes both its direct reference and expanded route at `q = 2²⁷ − 39`, the largest prime below 2²⁷, so the route comparison does not mix moduli while expansion gains one more bit of switching headroom. Those modulus bit lengths are at or below the **128-bit classical** row's `log q ≤ 27` ceiling in the *Homomorphic Encryption Security Standard* (HomomorphicEncryption.org, November 2018). That table assumes discrete-Gaussian error near `σ = 3.19`, while this lab uses a differently shaped centred-binomial law. The comparison is therefore only against the published bit ceiling, not a claim that the table's security estimate transfers. It also does not justify releasing key-dependent Galois hints: the evaluation-key path additionally relies on a circular-security assumption for that key-dependent BFV material. The page keeps both limitations visible.

**Not production cryptography.** A row of a 2018 table is an estimate under its stated distribution, not a proof or a certificate for this different distribution, and it says nothing about this implementation. Nothing is constant time; the direct server loop skips zero plaintext coefficients, so its running time depends on its own data; the secret key sits in ordinary browser memory; and none of it has been audited. Both "servers" are objects in one page, with no network involved. Each expansion is deliberately bounded to sixteen 512-byte records; four fixed blocks cover the 64-record catalog. Adding their folds into one answer has an inadequate, sample-dependent margin: deterministic regression samples include both exhausted answers and answers below half a bit. The bounded adaptation therefore returns all four fixed responses and spends four times the response bytes; the page measures the discarded sum from each run. This is not SealPIR's multi-dimensional recursion or production response path, and the page makes no claim that one ciphertext under this one-modulus engine can expand to 64 or 256 correct selectors. What **is** real is the mathematics — every displayed ciphertext, substitution, key switch, homomorphic multiply and noise measurement is computed, while displayed byte counts come from the serialized cryptographic buffers and timings come from the browser run. Transport framing and low-level instruction counts are not included.

---

## Exhibits

1. **The Shelf** — 64 public-domain works with real authors, dates and Library of Congress class letters. Pick one; that choice is the only secret in the protocol. Shows the exact 512-byte record a successful query returns, its SHA-256 integrity tag, and — behind a disclosure — the byte-to-coefficient packing, four bits at a time, taken from the record actually on screen. Also carries the **run seed**: pin one and the whole run becomes reproducible, including the secret key, with the warning that deserves.

2. **The Server's View** — the plaintext selection vector greyed out as *what never leaves your machine*, beside 64 opaque ciphertexts as *what the server gets*. Guess which one encrypts the `1`. Then a real distinguisher runs 40 trials and reports its measured accuracy against the 1-in-16 baseline — and a single clearly-marked switch reuses one random pair across every entry, at which point the same crude attack is right **every time**. Nothing about the attack changes; only the encryption does.

3. **Homomorphic Selection** — the headline mechanism, stepped. Fold one record, eight, or the rest, and watch all 64 light up as the server multiplies them in: this direct one-hot construction evaluates the encrypted selection over every record without learning which bit is the `1`. The **noise budget falls, measured** — the running ciphertext is decrypted and compared against what it ought to hold — beside the six-sigma prediction derived from the parameters alone. Until the chosen record is folded in, the accumulator decrypts to literal zero. At the end, one decryption produces a record the server never identified.

4. **Compressed Query** — the selected catalog record is retrieved twice from the full 64-record catalog: first with 64 direct ciphertexts, then with four fixed ciphertext blocks that expand to 64 selectors. Only the client knows which block carries `16⁻¹ · X^localIndex`; no block or index field crosses the wire. The panel serializes and round-trips the four reusable Galois keys, traces all four expansion rounds for each block, counts key-switch convolutions and all 64 record products, measures noise before and after expansion, and derives the upload-amortization crossover from actual buffers. It also shows the non-result: query compression leaves the 64-record scan intact and returns four responses to avoid exposing the selected block.

5. **One Server vs Two** — both protocols run over the identical shelf, with upload and download taken by serializing and milliseconds taken by timing. Two servers win every row that is a cost: cheaper, faster, exact. They lose exactly two, and the two are the same fact said twice — this scheme needs one server, so there is no non-collusion assumption to make. One red button spends the assumption they rest on — XOR the two masks and the index falls out in a single operation, with no cryptanalysis and no time. There is no equivalent button for the single-server column, and that is the trade. This table remains the original direct-path comparison; the Compressed Query panel separately compares both 64-record routes at its 27-bit modulus.

6. **Noise Exhaustion** — three knobs that all move real arithmetic: ciphertext modulus, record size, shelf length. Push until the budget reaches zero and the answer decrypts to garbage, reported through the record's own integrity tag and a count of coefficients outside the encodable range. Includes the parameter assessment against the published table, and a failure-code lab where each of the four codes is raised by a real input.

7. **What It Does Not Hide** — the negative claim, shown. Run queries and watch an observer's log fill with rows identical in **size** and different in **time**: fixed response length is a property of this construction, and occurrence, timing, frequency and identity are not. A table separates what the protocol hides from what a deployment would have to, and links forward to [Search Vault](https://systemslibrarian.github.io/crypto-lab-search-vault/) and [ORAM Vault](https://systemslibrarian.github.io/crypto-lab-oram-vault/).

---

## When to Use It

**Use single-server computational PIR when you cannot get non-collusion.** Two-server PIR is cheaper on every metric this lab measures, but it needs two operators under genuinely separate control — separate staff, separate jurisdictions, separate subpoena exposure. That is an organisational problem, not a technical one, and it is the reason single-server constructions get built at all.

**Use it when the query index is the sensitive thing** and the database is small enough, or the deployment rich enough, to pay the `O(N)` server work per query of this lab's one-dimensional construction. Query expansion reduces the query ciphertexts sent after setup; it does not remove the record products. That full scan is a property of this construction, not a requirement for every PIR scheme's online query phase.

**Preprocessing changes that tradeoff.** [Corrigan-Gibbs, Henzinger and Kogan, *Single-Server Private Information Retrieval with Sublinear Amortized Time* (EUROCRYPT 2022)](https://people.eecs.berkeley.edu/~henrycg/pubs/single-server/) use a linear-time setup to provide a client-held hint, then support a bounded number of adaptive queries with sublinear amortized server work. [Ma, Zhong, Rabin and Angel, *Incremental Offline/Online PIR* (ePrint 2021/1438; USENIX Security 2022)](https://eprint.iacr.org/2021/1438) study incremental preprocessing so database changes do not require restarting all preprocessing. These approaches trade setup, retained information and refresh work against online cost; this lab does not implement them.

**Do NOT use it as an access-control mechanism.** Nothing checks that your encrypted selection is one-hot, and nothing can — the server cannot read it. A malformed direct query can ask for a linear combination and receive its sum; malformed compressed blocks can yield one such result for each returned block. PIR bounds what the *server* learns, not what the *client* extracts.

**Do NOT use it when query-event metadata is sensitive.** With fresh randomness, the requested indices in a sequence of full-scan PIR queries remain hidden under the same stated multi-message assumptions. The occurrence, timing, count, rate and client identity of those queries remain visible. ORAM addresses a different problem: hiding data-dependent physical storage locations when a protocol does not scan every record.

**Do NOT use this code.** It is a teaching implementation. Real deployments use SEAL, OpenFHE or Lattigo.

---

## Live Demo

**https://systemslibrarian.github.io/crypto-lab-shelf-oracle/**

You can: pick any of 64 books; watch the encrypted selection vector be built and try to distinguish `Enc(1)` from `Enc(0)` yourself; break the encryption's randomness and watch a distinguisher go from chance to certain; step the homomorphic inner product record by record with a live measured noise budget; retrieve the same full-catalog record through direct and actually expanded compressed queries; run single-server and two-server PIR head to head with real byte counts; make the two servers collude and recover the index instantly; shrink the modulus until decryption returns garbage; trip all four failure codes; and watch what a network observer still sees after all of it.

---

## What Can Go Wrong

- **Decryption-feedback research — 20 October 2026.** Ordinary encryption security (IND-CPA), correct decryption, and security when an adversary learns computation results (IND-CPA-D) are different guarantees. Choe, Kang and Stehlé report attacks on particular BFV/BGV configurations using heuristic correctness assumptions, with experiments in OpenFHE and HElib. Crafted operations can exceed heuristic noise bounds; two attacks recover keys, while a third breaks indistinguishability. Parameter tables and noise estimates alone do not establish security in this feedback model. This browser lab does not reproduce those attacks or establish that its implementation is vulnerable. [Choe, Kang and Stehlé, *New IND-CPA-D Attacks on BFV and BGV*, ePrint 2026/2546](https://eprint.iacr.org/2026/2546), received 19 October and revised 20 October 2026; accepted to ACM CCS 2026. **Demonstrated results; attack-model-conditional.**

The threat model, and the four named failure codes.

**Who the adversary is.** An *honest-but-curious* server that follows the protocol and tries to learn the index from what it receives, plus a *passive network observer* that sees traffic but no plaintext. Privacy against the server is **computational**, resting on decision-RLWE at the parameters in use.

**What breaks it.**

- **`NOISE_BUDGET_EXHAUSTED`** — every record folded into the answer contributes its own encryption error, including the ones multiplied by an encrypted zero. Past the ceiling the answer still decrypts; it decrypts to garbage. The page detects it three ways, and reports them separately because only two are things a real client could do: the record's own SHA-256 tag fails, coefficients come back outside `[0, 16)` where the encoder can never put them, and — using the secret key and the true record, which a real client has neither of — the measured budget reaches zero. **A deployment sizes its parameters in advance; it does not discover exhaustion at runtime.**
- **`PARAM_UNSAFE`** — the modulus bit length exceeds the cited HES 2018 128-bit-row ceiling for this ring degree, or would push this implementation past 2⁵³ where JavaScript integers stop being exact. The first means even the page's limited reference comparison no longer applies; it does not by itself prove insecurity. The second is more immediate: past that bound JavaScript arithmetic is not exact, so the demo could produce plausible garbage while claiming exactness.
- **`DIM_MISMATCH`** — the query is not the same length as the shelf. Refused **before any homomorphic work**, because a short query answers over a prefix and a long one reads past the end, and both return a ciphertext that decrypts to something.
- **`INDEX_OUT_OF_RANGE`** — the requested shelf position does not exist.

**What the protocol does not defend against.**

- **A malicious server.** PIR provides no integrity. A server that wants to lie can return a different record with a matching tag; the tag is part of the record it holds. Verifiable PIR is a separate line of work.
- **Traffic metadata.** Occurrence, timing, frequency, count, client identity and database shape all leak. What does *not* leak is the index: the direct route always returns one ciphertext, while the compressed route always returns four, whichever record was requested. The direct observer exercise sends one ciphertext per shelf position; the compressed route sends four fixed query blocks after its reusable Galois-key setup. Those lengths are visible and fixed for the 64-record shape — they do not vary with the chosen index. Padding and traffic shaping are separate mechanisms for the things that do leak; PIR does not claim them.
- **Repeated queries.** With fresh randomness, each requested index — and therefore the requested-index sequence — remains hidden under the same stated multi-message RLWE and circular-security assumptions. Query occurrence, timing, count, rate and client identity remain visible. ORAM instead hides data-dependent physical storage accesses; this construction performs the same full 64-record scan for every query.
- **A malformed client query.** Unauthenticated by construction — see *When to Use It*.
- **Side channels.** Nothing here is constant time. The server's inner loop skips zero plaintext coefficients, so its running time depends on its own data; that costs nothing in this demo because the shelf is public, and it is exactly the shortcut a deployment must not take.

---

## Real-World Usage

Single-server PIR is a live research and deployment area, not a museum piece.

- **SealPIR** (Angel–Chen–Laine–Setty, IEEE S&P 2018) uses **query expansion**: for a dimension that fits in one BFV polynomial, the client sends one ciphertext plus reusable Galois keys and the server expands it into the selection vector with substitutions and key switching. This lab executes that mechanism over sixteen positions per ciphertext and uses four fixed blocks to cover its 64-record catalog without revealing the selected block. It does not implement SealPIR's multi-dimensional recursion, modulus switching, seeded ciphertext compression or production parameter sets, and it copies none of the paper's benchmark numbers.
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
- **[ORAM Vault](https://systemslibrarian.github.io/crypto-lab-oram-vault/)** — Path ORAM hides a logical access sequence from a server that observes data-dependent physical storage locations. Shelf Oracle instead performs the same full 64-record scan for every query; its visible query-event timing and count are traffic-metadata problems, not an index-dependent storage trace.

---

## Build & Verify

**99 unit tests** across seven files, all passing (`npm test`).

**Primary-source anchors.** Five published sources bound the implementation and its claims. The first two supply values that the suite checks directly; the others define the construction, expansion schedule and security caveat rather than serving as invented interoperability vectors:

- **RFC 8439** (*ChaCha20 and Poly1305 for IETF Protocols*) — the §2.3.2 block-function vector and the §2.4.2 encryption vector, in `src/pir/chacha20.test.ts`. ChaCha20 is the sampler every ciphertext on the page is drawn from, so this is the anchor under the randomness layer.
- **The Homomorphic Encryption Security Standard** (HomomorphicEncryption.org, November 2018) — all **18 published modulus ceilings** of the uniform-ternary-secret classical table (`n ∈ {1024 … 32768}` × `{128, 192, 256}`-bit), checked one row at a time in `src/pir/records.test.ts`. Its error is discrete Gaussian; this lab's error is centred binomial. Tests require the UI to label the result as a bit-size comparison rather than transferring the table's security estimate. `PARAM_UNSAFE` marks a modulus above the cited 128-bit-row ceiling (or an exact-arithmetic failure), not a proof of insecurity.
- **Fan and Vercauteren, *Somewhat Practical Fully Homomorphic Encryption*** ([IACR ePrint 2012/144](https://eprint.iacr.org/2012/144)) — the BFV construction from which this teaching implementation takes its ciphertext convention and key-switching setting.
- **Angel, Chen, Laine and Setty, *PIR with Compressed Queries and Amortized Query Processing*** ([IACR ePrint 2017/1142](https://eprint.iacr.org/2017/1142)) and the [Microsoft SealPIR implementation](https://github.com/microsoft/SealPIR/blob/master/src/pir_server.cpp) — the paper's server-side inverse scaling and the implementation's algebraically equivalent client pre-scaling, plus the odd-automorphism expansion schedule exercised here.
- **Geelen and Vercauteren, *Fully Homomorphic Encryption for Cyclotomic Prime Moduli*** ([IACR ePrint 2024/1587](https://eprint.iacr.org/2024/1587)) — an explicit statement of the distinction the UI preserves: an IND-CPA reduction without evaluation keys does not by itself establish security for key-dependent evaluation material; the latter invokes a circular-security assumption.

BFV and SealPIR do not supply interoperability test vectors for this implementation, so the rest of the suite uses independent definitions and cross-checks rather than pretending otherwise. The original path's strongest check is a **three-way cross-scheme agreement**: single-server RLWE PIR, two-server XOR PIR and a plain array read must return the identical bytes. The compressed path independently requires the direct BFV query, the expanded query and the separately built catalog record to agree byte for byte and pass the embedded SHA-256 tag.

Also covered: the negacyclic property checked directly (`X^(n-1) · X = -1`, not `+1` — a cyclic ring round-trips perfectly and no correctness test would notice); schoolbook multiplication against a definitional oracle; the new NTT/CRT products against a separate quadratic definition, including the wraparound sign and an executable exactness bound; BFV round-trips over every plaintext value; additive homomorphism; that reused randomness makes `Enc(1) − Enc(0)` exactly `Δ`; every raw switch-key sample checked against `B^j · σ(s)` with its sampled error bound; the published odd substitution schedule; all sixteen one-hot expansion positions at the shipped modulus; full-catalog direct/expanded/plain retrieval agreement for an index outside the first block; positive but smaller post-expansion noise; canonical evaluation-key serialization and refusal of missing, truncated, mismatched and noncanonical setup material; detection that a canonical but corrupted evaluation key changes the output; an exact server-query shape with no block or index field; that the stepped fold reaches the same ciphertext as the one-shot server; that a partial answer decrypts to zero until the chosen record is folded in; that the measured budget falls monotonically; that the six-sigma prediction is a bound the measurement respects; UTF-8 truncation that never splits a sequence; wire-format round-trips at every modulus; and every failure code, raised and named.

**The browser gate** (`npm run test:a11y`) runs two suites against the production build:

- **`e2e/a11y.spec.ts`** — zero WCAG 2.1 A/AA violations, at 1280px, 380px and 280px, across roughly forty driven states per width. It is not an axe wrapper: it asserts axe's `incomplete` bucket as well as `violations` (which is where `aria-prohibited-attr` and every `color-mix()` contrast decision live), computes contrast arithmetically over composited backdrops, measures non-text contrast per border side against a ratchet baseline that is currently **empty**, and adds reflow, scroller-reachability and invisible-focus-target oracles that axe has no rules for. Reduced motion is set through `emulateMedia` and asserted from inside the page; nothing is injected and no panel is revealed from script.
- **`e2e/claims.spec.ts`** — 29 tests that check the page tells the truth, by comparing values the page itself printed rather than hardcoded strings: the record the fold returns against the record the shelf shows; the budget ceiling re-derived as `log2(⌊q/t⌋)` from the printed ring parameters; the query size re-derived from `n` and `log q` where the source measures a serialized buffer; the compressed-query buffer ledger, substitution schedule and executed operation counters independently re-derived; direct, expanded and plain-record bytes compared; the head-to-head upload against the Server's View figure; each failure code naming its actual cause with numbers that match the controls on screen; verdict **retirement** (change a parameter or key and the stale measurement is gone *and the page says why*) alongside a **no-op guard** (re-selecting the same book retires nothing); the `[hidden]` cascade probe; and that the page does not fight its reader — focus stays on the control you activated across the rebuild, the live region is one node that survives every render, and a demonstration failure code does not overwrite a real retrieval verdict.

**Defects found by the gate and by an adversarial review pass, and fixed rather than baselined:** `.panel { display: grid }` outranking the UA's `[hidden]` rule, which left six tabpanels in the tab order painting nothing; a missing `box-sizing: border-box` plus the grid `min-width: auto` default, which pushed the document sideways at 380px; `aria-label` on role-less tiles; keyboard focus being thrown to `<body>` on every re-render; live regions rebuilt inside a cleared subtree, so none of them could announce anything; a demonstration failure code overwriting a real retrieval verdict; a retirement reason latched on the first change; a hidden panel re-encrypting a 64-ciphertext query nobody was looking at; the comparison table conveying "better" by colour alone; and two rows of the what-is-hidden table contradicting each other about query length.

**Mutation-tested.** A green suite is not evidence until it has been watched failing. Twelve mutations were applied one at a time. The original eight cover the negacyclic sign in the direct ring, the `DIM_MISMATCH` guard, fresh encryption randomness, the `[hidden]` rule, the no-op selection guard, focus restoration, live-region persistence, and the on-screen-panel re-render. Four more target the compressed path: the odd Galois schedule, the automorphism's negacyclic sign, preservation of the substituted `c0` term during key switching, and subtraction rather than addition when the NTT convolution is folded modulo `X^n + 1`. Each was seen to fail its owning test by name and the edited source files were restored to their identical SHA-256 hashes before the full 99-test rerun.

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

That table is the original 64-record **direct** baseline at its default 26-bit modulus. The separate Compressed Query exhibit compares both routes over all 64 records at the expansion path's 27-bit modulus. A ciphertext is 6,912 bytes: the 64-ciphertext direct query is 442,368 bytes, while four fixed compressed-query blocks total 27,648 bytes. Four binary Galois keys serialize to 746,520 reusable setup bytes, so the first compressed upload totals 774,168 bytes and cumulative compressed upload becomes smaller on query two. The direct response is 6,912 bytes; the compressed server returns four fixed responses totaling 27,648 bytes so response shape does not reveal the selected block. Both routes still perform 64 record products. Those figures are derived from actual serialized buffers; the exhibit separately measures the reader's timings and noise. Seeded compression of the uniform ciphertext half remains unimplemented and is named rather than assumed.

Noise budget at those defaults: the ceiling is `log2(⌊q/t⌋) = 21.91` bits, a freshly encrypted record measures about **16.5** bits — encryption spends roughly five bits on its own sampled error before the server does anything — and the finished 64-record answer measures about **7.6**. At `q = 2¹⁸` the same query exhausts and the page says so through the record's own integrity tag.

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*

