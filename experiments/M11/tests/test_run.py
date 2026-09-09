from __future__ import annotations
import importlib.util,json,tempfile,unittest
from pathlib import Path
import jsonschema
ROOT=Path(__file__).resolve().parents[3]
def load(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);assert s and s.loader;s.loader.exec_module(m);return m
M11=load("m11",ROOT/"experiments/M11/run.py")
class M11Tests(unittest.TestCase):
 def analyze_fixture(self,rows):
  with tempfile.TemporaryDirectory() as t:
   root=Path(t);p=root/"rows.json";p.write_text(json.dumps({"schema_version":"0.1","feature_definition_version":"0.1","rows":rows}),encoding="utf-8");return M11.analyze(p,root/"out",task="application")
 def test_absent_labels_are_not_scored(self):
  result=self.analyze_fixture([{"id":"a","group_id":"g","features":{"bytes":1}}]);self.assertEqual("insufficient_labels",result["status"]);self.assertIsNone(result["metrics"])
 def test_single_class_is_not_scored(self):
  result=self.analyze_fixture([{"id":"a","group_id":"g1","labels":{"application":"x"},"features":{"bytes":1}},{"id":"b","group_id":"g2","labels":{"application":"x"},"features":{"bytes":2}}]);self.assertEqual("insufficient_labels",result["status"]);self.assertIsNone(result["model"])
 def test_empty_is_explicit(self):self.assertEqual("empty",self.analyze_fixture([])["status"])
 def test_grouped_synthetic_data_can_train_without_group_overlap(self):
  rows=[]
  for index in range(12):
   label="alpha" if index%2 else "beta";rows.append({"id":str(index),"group_id":f"g{index}","labels":{"application":label},"features":{"bytes":100 if label=="alpha" else 1,"packets":10 if label=="alpha" else 1}})
  result=self.analyze_fixture(rows);self.assertEqual("ok",result["status"]);self.assertEqual([],result["split"]["group_overlap"]);self.assertIsNotNone(result["metrics"])
 def test_result_validates_against_module_schema(self):
  schema=json.loads((ROOT/"research/M11-behavior-classification/classification.schema.json").read_text(encoding="utf-8"));jsonschema.validate(self.analyze_fixture([]),schema)
if __name__=="__main__":unittest.main()

