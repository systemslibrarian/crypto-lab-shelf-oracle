8. Shelf Oracle

crypto-lab-shelf-oracle · PRIVACY · completes Patron Shield → Oblivious Shelf → Shelf Oracle

Thesis. Two-server PIR buys information-theoretic privacy by assuming non-collusion. Single-server computational PIR removes that assumption — and this is what removing it costs. (Not "deployed PIR has one server": two-server architectures are active and practical, and the lab is about the trade, not about one side being obsolete.)

Construction. Computational single-server PIR, RLWE-based, SealPIR-style (Angel et al., IEEE S&P 2018). The baseline client encrypts a direct selection vector under BFV; the server computes the inner product homomorphically; one ciphertext returns. A separate act covers the same 64 records with four fixed ciphertext blocks: one client-prescaled monomial block and three encrypted-zero blocks expand to 64 selectors through real Galois substitution and key switching. All four queries are sent, all 64 records are scanned and all four responses return. No plaintext block or index field is sent; the choice is present only under encryption and hidden under the stated assumptions. Reusable evaluation-key bytes, operation counts and noise stay visible. Multi-dimensional indexing remains out of scope; query compression must not be described as sublinear server work.

Acts
The catalog. 64 books. Pick one.
The server's view. 64 ciphertexts arrive; the server cannot distinguish the one-hot position. Show the encrypted selection vector as opaque bytes and the plaintext version beside it, greyed, as what the server does not get.
Homomorphic selection. Step the inner product. Watch the noise budget fall — the meter FHE Arena already teaches, now doing something.
Compressed query. Retrieve the same full-catalog record with 64 direct one-hot ciphertexts and four fixed blocks expanded server-side. Count the reusable evaluation keys, serialized queries and responses, substitutions, key switches, all 64 record products and measured noise. Keep the sixteen-selectors-per-ciphertext correctness bound visible.
Head to head with Oblivious Shelf. One server versus two. Computational versus information-theoretic. Measured timings and byte counts for both on the same catalog. The tradeoff is the lab.
Noise exhaustion. Push the database size until the budget runs out and decryption returns garbage. NOISE_BUDGET_EXHAUSTED.

Negative claim (NEG-1). PIR hides the selected index under its security model. It does not inherently hide query occurrence, timing, frequency, database size, or other traffic metadata. Padding and traffic shaping are separate mechanisms — note that SealPIR-style responses are fixed-size by construction, so response length is one thing this design does cover, and say which properties come from the protocol versus from the deployment. Link forward to Search Vault's leakage-abuse attacks and ORAM Vault's access-pattern hiding.

Failure codes. NOISE_BUDGET_EXHAUSTED · DIM_MISMATCH · PARAM_UNSAFE · INDEX_OUT_OF_RANGE

Repo description.

Browser demo: single-server RLWE private information retrieval over a 64-book catalog — no second server, no collusion assumption, one homomorphic multiply per record. Watch the noise budget pay for what the second server used to.
