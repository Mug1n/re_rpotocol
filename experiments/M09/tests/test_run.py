from __future__ import annotations
import importlib.util, json, tempfile, unittest
from pathlib import Path
import jsonschema
ROOT=Path(__file__).resolve().parents[3]
def module(name:str,path:Path):
    spec=importlib.util.spec_from_file_location(name,path); value=importlib.util.module_from_spec(spec); assert spec and spec.loader; spec.loader.exec_module(value); return value
M09=module("m09",ROOT/"experiments/M09/run.py")
def m01(missing_time:bool=False):
    packets=[]
    for index,(time,src,dst,size) in enumerate((("1.0","a","b",10),("1.1","b","a",20),("1.2","a","b",30),("1.3","a","b",40))):
        packets.append({"id":f"p{index}","index":index,"timestamp_epoch":None if missing_time and index==2 else time,"captured_length":size,"src_ip":src,"src_port":1 if src=="a" else 2,"dst_ip":dst,"dst_port":1 if dst=="a" else 2,"truncated":False,"analysis":{"retransmission":False,"out_of_order":False,"gap_or_loss":False}})
    return {"schema_version":"0.1","packets":packets,"flows":[{"id":"f1","packet_ids":["p0","p1","p2","p3"],"node0":{"ip":"a","port":1},"node1":{"ip":"b","port":2}}]}
class M09Tests(unittest.TestCase):
 def analyze_fixture(self,value):
    with tempfile.TemporaryDirectory() as temp:
      root=Path(temp); source=root/"m01.json"; source.write_text(json.dumps(value),encoding="utf-8"); result=M09.analyze(source,root/"out"); return result
 def test_bidirectional_statistics_are_hand_calculable(self):
    flow=self.analyze_fixture(m01())["flows"][0]; self.assertEqual(100,flow["byte_count"]);self.assertEqual(80,flow["directional"]["node0_to_node1"]["bytes"]);self.assertEqual(0.3,flow["duration_seconds"]);self.assertEqual(4,flow["burst"]["max_packets"])
 def test_missing_time_is_explicit(self):
    result=self.analyze_fixture(m01(True));self.assertEqual("partial",result["status"]);self.assertIsNone(result["flows"][0]["duration_seconds"]);self.assertTrue(result["unavailable_features"])
 def test_raw_input_is_insufficient_metadata(self): self.assertEqual("insufficient_metadata",self.analyze_fixture({"schema_version":"0.1","packets":[],"flows":[]})["status"])
 def test_refuses_existing_output(self):
    with tempfile.TemporaryDirectory() as temp:
      root=Path(temp);source=root/"m.json";source.write_text(json.dumps(m01()),encoding="utf-8");out=root/"out";out.mkdir()
      with self.assertRaises(FileExistsError):M09.analyze(source,out)
 def test_result_validates_against_module_schema(self):
    schema=json.loads((ROOT/"research/M09-flow-features/flow-features.schema.json").read_text(encoding="utf-8"));jsonschema.validate(self.analyze_fixture(m01()),schema)
if __name__=="__main__":unittest.main()

