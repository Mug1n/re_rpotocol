# Architecture and autonomous work

The project uses a branch-aware task graph instead of forcing every input through every module. M01 preserves raw bytes and validated capture metadata. M02 describes bytes. M03–M06 analyze explicitly admitted message sources. M07 records dissector evidence. B's payload-source layer maps strict HTTP framing to exact stream ranges before M08 performs bounded recovery. M09–M10 describe flow statistics and non-semantic behavior patterns. M11 separates grouped training/evaluation from label-free prediction. M12 normalizes validated records into stable evidence IDs. A bounded model may explain those facts, while C's verifier independently decides acceptance.

Reusable tools include Python, jsonschema, TShark/Wireshark, scikit-learn and joblib. Project-specific work includes the artifact schemas, byte-range and hash contracts, conservative framing/alignment/field logic, HTTP source mapper, model/prediction adapters, profile-driven orchestration and independent acceptance gate.

The trust chain is byte-oriented: input hash → module artifact hash → source references and half-open ranges → recovered/classified/report artifacts → independent truth and gate. JSON existence alone is never treated as successful recovery, classification, semantic explanation or acceptance.
