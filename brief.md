8. Shelf Oracle

crypto-lab-shelf-oracle · PRIVACY · completes Patron Shield → Oblivious Shelf → Shelf Oracle

Thesis. Two-server PIR buys information-theoretic privacy by assuming non-collusion. Single-server computational PIR removes that assumption — and this is what removing it costs. (Not "deployed PIR has one server": two-server architectures are active and practical, and the lab is about the trade, not about one side being obsolete.)

Construction. Computational single-server PIR, RLWE-based, SealPIR-style (Angel et al., IEEE S&P 2018) reduced to the direct one-hot form. Client encrypts a selection vector under BFV; server computes the inner product homomorphically; one ciphertext returns. Build on the BFV implementation already in FHE Arena. Hold the catalog to 64–256 items and state the scaling honestly — full SealPIR with query expansion and multi-dimensional indexing is out of browser scope, and saying so beats faking it.

Acts
The catalog. 64 books. Pick one.
The server's view. 64 ciphertexts arrive; the server cannot distinguish the one-hot position. Show the encrypted selection vector as opaque bytes and the plaintext version beside it, greyed, as what the server does not get.
Homomorphic selection. Step the inner product. Watch the noise budget fall — the meter FHE Arena already teaches, now doing something.
Head to head with Oblivious Shelf. One server versus two. Computational versus information-theoretic. Measured timings and byte counts for both on the same catalog. The tradeoff is the lab.
Noise exhaustion. Push the database size until the budget runs out and decryption returns garbage. NOISE_BUDGET_EXHAUSTED.

Negative claim (NEG-1). PIR hides the selected index under its security model. It does not inherently hide query occurrence, timing, frequency, database size, or other traffic metadata. Padding and traffic shaping are separate mechanisms — note that SealPIR-style responses are fixed-size by construction, so response length is one thing this design does cover, and say which properties come from the protocol versus from the deployment. Link forward to Search Vault's leakage-abuse attacks and ORAM Vault's access-pattern hiding.

Failure codes. NOISE_BUDGET_EXHAUSTED · DIM_MISMATCH · PARAM_UNSAFE · INDEX_OUT_OF_RANGE

Repo description.

Browser demo: single-server RLWE private information retrieval over a 64-book catalog — no second server, no collusion assumption, one homomorphic multiply per record. Watch the noise budget pay for what the second server used to.