# Installation and use

## Requirements

- Python 3.11 or newer; the integration run was checked with Python 3.13.9.
- Packages in `requirements.txt`.
- Wireshark/TShark for fresh PCAP/PCAPNG extraction. Pass its exact path with `--tshark`; PATH absence alone is not proof that Wireshark is missing.
- No model credential is needed for deterministic analysis or replay of the saved, key-free model evidence.

```powershell
python -m pip install -r requirements.txt
python -B scripts/analyze.py --input data/fixtures/m01-raw.dat --profile profiles/portable.json --output-dir tmp/portable-run
python -B scripts/analyze.py --input data/acceptance/frozen-20260910/captures/download-01.pcapng --profile profiles/acceptance.json --output-dir tmp/acceptance-run
python -B scripts/verify_acceptance.py data/acceptance/frozen-20260910/full-chain/acceptance.json
```

The current Windows integration host keeps Wireshark 4.6.8 at `third_party/Wireshark`, which is intentionally excluded from Git. Use `--tshark ".\third_party\Wireshark\tshark.exe"` and set `$env:WIRESHARK_HOME = "$PWD\third_party\Wireshark"` before the M01 test suite. Another checkout must install its own trusted Wireshark copy. Npcap is only required for live interface capture, not for reading saved PCAP/PCAPNG files.

Output directories must be new. Use `--invoke-model` only when an authorized `DEEPSEEK_API_KEY` is in the current process environment; this can incur external processing or cost. Never store the key in the repository.

To package a clean committed checkout:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/package_submission.ps1 -OutputZip ..\re_rpotocol-submission.zip
```

Extract the ZIP into a new directory, install dependencies, rerun the acceptance verifier and the two analysis commands, and compare the recovered SHA-256 before treating the package as portable.
