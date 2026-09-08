from __future__ import annotations
import importlib.util,json,tempfile,unittest
from pathlib import Path
import jsonschema
ROOT=Path(__file__).resolve().parents[3]
def load(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);assert s and s.loader;s.loader.exec_module(m);return m
M10=load("m10",ROOT/"experiments/M10/run.py")
def features(missing=False):return {"schema_version":"0.1","flows":[{"flow_id":"f","node0_to_node1_byte_ratio":.9,"packet_interarrival_seconds":{"count":3,"mean":1,"max":12},"interarrival_cv":.05,"burst":{"max_packets":4},"duration_seconds":80}],"unavailable_features":[{"flow_id":"f","feature":"duration_iat_rate_burst"}] if missing else []}
class M10Tests(unittest.TestCase):
 def analyze_fixture(self,x):
  with tempfile.TemporaryDirectory() as t:
   root=Path(t);p=root/"in.json";p.write_text(json.dumps(x),encoding="utf-8");return M10.analyze(p,root/"out")
 def test_rules_are_nonexclusive(self):
  result=self.analyze_fixture(features());self.assertEqual({"direction_dominance","periodicity_candidate","bursty_transfer","long_lived_intermittent"},{x["type"] for x in result["observations"]})
 def test_missing_time_keeps_only_non_temporal_rule(self):
  result=self.analyze_fixture(features(True));self.assertEqual("partial",result["status"]);self.assertEqual(["direction_dominance"],[x["type"] for x in result["observations"]])
 def test_result_validates_against_module_schema(self):
  schema=json.loads((ROOT/"research/M10-behavior-analysis/behaviors.schema.json").read_text(encoding="utf-8"));jsonschema.validate(self.analyze_fixture(features()),schema)
if __name__=="__main__":unittest.main()

