# Test and acceptance analysis

The verification layers are:

1. M01–M12 module unit tests for algorithms, schemas, budgets and atomic failure.
2. Cross-module tests for real external DAT, HTTP payload recovery, A orchestration, frozen data/classification and C's independent gate.
3. A frozen full-chain acceptance manifest whose recovered bytes, label-free prediction and real key-free model records are independently hash checked.
4. Public corpus replay, reported separately from the controlled acceptance data.

Core commands:

```powershell
python -B -m unittest discover -s experiments/M01/tests -v
# repeat M02 through M12
python -B -m unittest discover -s experiments/tests -v
python -B scripts/verify_acceptance.py data/acceptance/frozen-20260910/full-chain/acceptance.json
```

Known environment limitation on the current integration host: Python 3.13.9 is available, but `C:\Program Files\Wireshark\tshark.exe` is absent. Six M01 tests that require Wireshark are skipped and are not counted as passed. Frozen C artifacts record the separate capture host's TShark 4.6.8 evidence. The controlled classifier metrics are not a claim of broad real-world generalization.
