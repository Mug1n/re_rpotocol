# Detailed design

## Input and orchestration

`scripts/analyze.py` validates a versioned profile and constructs only the requested DAG. Every stage records status and elapsed time. Artifacts live in an array with module, instance, scope, length and SHA-256, so multiple streams or M08 bodies cannot overwrite one another. A failed stage removes the incomplete run directory and publishes an adjacent machine-readable failure record.

The analysis interface does not accept truth or evaluation labels. A reused M01 must validate against its schema, internal artifact references and the exact supplied input hash. The acceptance profile uses frozen M01/M07 only because the portable integration host lacks TShark; fresh hosts can use a profile without reuse and pass `--tshark`.

## Protocol, structure and recovery

HTTP recognition requires a valid request/response start line and framing headers. Content-Length maps to one half-open range; chunked data maps to multiple ranges. M08 rechecks M01, stream, range reconstruction and body hashes, then applies bounded UTF/Hex/Base64/gzip/zlib transformations. Partial transport stays partial; Brotli and no-key encryption are explicit skips.

M03 rules retain their origin in the A run-manifest scope. Protocol- or format-declared rules are not relabeled as automatic inference. M05 rows must reconstruct the original bytes after gaps are removed; M06 hypotheses remain statistical candidates.

## Behavior, classification and reporting

M09 derives flow features only when M01 metadata exists. M10 emits threshold observations without application intent. M11 model artifacts are hash-bound and prediction rows are label-free. M12 validates upstream references, accepts multiple artifacts per module and creates deterministic evidence IDs. The DeepSeek adapter caps evidence/request/response sizes, treats evidence text as untrusted data, rejects unknown citations and prohibited unsupported security conclusions, and writes no API key.

## Acceptance

`scripts/verify_acceptance.py` is owned by C and independently checks module coverage, hashes, recovery truth, classifier/model binding and the saved raw model response. Analysis `complete` and acceptance `PASS` are distinct states.
