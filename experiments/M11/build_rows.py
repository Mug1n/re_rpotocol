#!/usr/bin/env python3
"""Build fixed M11 feature rows from an M09 artifact; labels stay external."""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path

VERSION = "0.1"
FEATURES = ("packet_count", "byte_count", "duration_seconds", "rate_bytes_per_second", "direction_switches", "node0_to_node1_byte_ratio", "burst_count", "burst_max_packets", "iat_mean", "iat_p95")

def digest(path: Path) -> str: return hashlib.sha256(path.read_bytes()).hexdigest()
def build(source: Path, output: Path) -> dict:
    if output.exists(): raise FileExistsError(f"output already exists: {output}")
    raw = json.loads(source.read_text(encoding="utf-8"))
    if raw.get("schema_version") != VERSION or not isinstance(raw.get("flows"), list): raise ValueError("expected M09 flow_features.json")
    rows=[]
    for flow in sorted(raw["flows"], key=lambda item: item["flow_id"]):
        iat=flow["packet_interarrival_seconds"]; burst=flow["burst"]
        values={"packet_count":flow["packet_count"],"byte_count":flow["byte_count"],"duration_seconds":flow["duration_seconds"],"rate_bytes_per_second":flow["rate_bytes_per_second"],"direction_switches":flow["direction_switches"],"node0_to_node1_byte_ratio":flow["node0_to_node1_byte_ratio"],"burst_count":burst["count"],"burst_max_packets":burst["max_packets"],"iat_mean":iat["mean"],"iat_p95":iat["p95"]}
        if any(value is None for value in values.values()): continue
        rows.append({"id":flow["flow_id"],"group_id":None,"labels":{},"features":{key:float(values[key]) for key in FEATURES}})
    result={"schema_version":VERSION,"feature_definition_version":VERSION,"source":{"module":"M09","artifact_path":str(source),"artifact_sha256":digest(source)},"feature_names":list(FEATURES),"rows":rows,"warnings":["Labels and split assignments are intentionally absent; add them only in the isolated training-preparation step."]}
    output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n",encoding="utf-8");return result
def main(argv=None):
 p=argparse.ArgumentParser();p.add_argument("input",type=Path);p.add_argument("--output",required=True,type=Path);a=p.parse_args(argv);build(a.input,a.output);print(a.output)
if __name__=="__main__":main()
