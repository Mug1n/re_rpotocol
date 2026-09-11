# ABC acceptance pipeline contract

Schema version: `0.1`. Owner: A. Consumers: B and C.

## Single-input command

```powershell
python -B scripts/analyze.py --input <file.dat> --profile <profile.json> --output-dir <new-directory> [--tshark <tshark.exe>]
```

The analysis command never accepts truth or test labels. `--invoke-model` is opt-in and requires `DEEPSEEK_API_KEY` only in process memory; without that flag no external request occurs. The output directory must not exist. A successful invocation writes `run_manifest.json`; a stage failure removes the incomplete output directory and writes the adjacent `<name>.failure.json`, then exits 2.

Profiles validate against `research/analysis-profile.schema.json`. Relative reusable-artifact paths first resolve from the caller's working directory, then from the profile directory. `profiles/portable.json` performs M01/M02/direct-M08/M12 without network prerequisites. `profiles/acceptance.json` binds the frozen C sample to verified M01/M07/M11 artifacts and reruns all independent downstream stages.

## Run manifest

`research/run-manifest.schema.json` defines a versioned manifest with:

- input and profile path, byte length and SHA-256;
- Python/platform and the exact TShark path/version or an explicit unavailable state;
- every requested stage with `completed`, `reused_verified`, `blocked`, or `failed` and elapsed time;
- an artifact array, never a module-key dictionary;
- optional scope values such as stream, direction, payload source and framing-rule origin;
- model state `not_requested`, `blocked`, or `invoked`.

Each artifact record contains `module`, stable `instance_id`, path, length, SHA-256, schema version, producer status and scope. Multiple records may share a module—for example one M08 result per HTTP body—but `(module, instance_id)` must identify a single instance. M12 also accepts repeated `--input M08=...` arguments and retains each input record.

## Cross-role records

### B → A

`payload_sources.json` validates against `research/M08-recovery/payload-sources.schema.json`. Every source must identify its M01 stream, flow, direction and message index; carry `recognition_basis=strict_http_start_line_and_framing_headers`; preserve one or more half-open source ranges; and bind the body artifact by length and SHA-256. A revalidates the M01 parent, stream artifact, ranges and body before M08.

### C → A

The data manifest and truth remain separate. A receives only the selected capture for analysis. Reused C artifacts are accepted only after their own schema/source/hash checks. Label-free prediction rows contain no truth labels, and prediction must bind to the recorded classifier model hash and feature version.

### A → C

C receives `run_manifest.json` plus the independently assembled `acceptance.json`. The latter remains governed by `research/acceptance.schema.json` and `scripts/verify_acceptance.py`; analysis success alone is not acceptance success. C verifies input/module hashes, recovered bytes against separate truth, model request/response provenance, classifier prediction/model binding and required M01–M11 coverage.

## Minimal examples

Valid multi-instance fragment:

```json
{
  "artifacts": [
    {"module": "M08", "instance_id": "recovery-0000", "scope": {"direction": "node0_to_node1"}},
    {"module": "M08", "instance_id": "recovery-0001", "scope": {"direction": "node1_to_node0"}}
  ]
}
```

Invalid cases include a reused M01 whose input hash differs, two identical M12 module/path inputs, a payload range that cannot rebuild the extracted body, an unknown model evidence ID, and a `complete` acceptance record without M01–M11. These cases must fail without a usable output directory.
