#!/usr/bin/env python3
"""M10: deterministic, non-semantic behaviour observations from M09."""
from __future__ import annotations
import argparse, hashlib, json, sys
from pathlib import Path
from typing import Any

VERSION = "0.1"
def digest(path: Path) -> str: return hashlib.sha256(path.read_bytes()).hexdigest()
def load(path: Path) -> dict[str, Any]:
    try: value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc: raise ValueError(f"invalid M09 JSON: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema_version") != VERSION: raise ValueError("unsupported M09 artifact")
    if not isinstance(value.get("flows"), list): raise ValueError("M09 flows must be an array")
    return value
def observation(flow: dict[str, Any], kind: str, values: dict[str, Any], thresholds: dict[str, Any], limitations: list[str]) -> dict[str, Any]:
    return {"behavior_id": f"{flow.get('flow_id')}:{kind}", "flow_id": flow.get("flow_id"), "type": kind,
            "observed_values": values, "thresholds": thresholds,
            "evidence_refs": [{"record_id": flow.get("flow_id"), "feature_definition_version": VERSION}],
            "confidence_basis": "deterministic threshold rule", "limitations": limitations}
def analyze(input_path: Path, output_dir: Path, *, dominance: float=.8, periodic_cv: float=.1, minimum_iats: int=3, burst_packets: int=3, long_seconds: float=60., idle_seconds: float=10.) -> dict[str, Any]:
    if output_dir.exists(): raise FileExistsError(f"output directory already exists: {output_dir}")
    source = load(input_path)
    rules = {"version": VERSION, "direction_dominance_ratio": dominance, "periodicity_max_iat_cv": periodic_cv,
             "periodicity_min_iats": minimum_iats, "bursty_min_packets": burst_packets, "long_lived_min_seconds": long_seconds, "intermittent_idle_min_seconds": idle_seconds}
    result: dict[str, Any] = {"schema_version": VERSION, "source": {"module":"M09", "artifact_path":str(input_path), "artifact_sha256":digest(input_path), "record_count":len(source["flows"])},
      "status":"ok", "parameters":rules, "rule_set":rules, "metrics":{"flow_count":len(source["flows"]), "observation_count":0}, "observations":[], "insufficient_scopes":[], "warnings":[]}
    for flow in sorted(source["flows"], key=lambda x: str(x.get("flow_id", ""))):
        fid = flow.get("flow_id")
        unavailable = {x.get("feature") for x in source.get("unavailable_features", []) if x.get("flow_id") == fid}
        ratio = flow.get("node0_to_node1_byte_ratio")
        if isinstance(ratio, (int,float)):
            if max(ratio, 1-ratio) >= dominance:
                result["observations"].append(observation(flow, "direction_dominance", {"node0_to_node1_byte_ratio":ratio}, {"minimum_dominant_ratio":dominance}, ["Directions are node-relative, not client/server roles."]))
        else: result["insufficient_scopes"].append({"flow_id":fid,"rule":"direction_dominance","reason_code":"directional_bytes_unavailable"})
        iat = flow.get("packet_interarrival_seconds", {})
        cv = flow.get("interarrival_cv")
        if "duration_iat_rate_burst" in unavailable:
            for rule in ("periodicity_candidate","bursty_transfer","long_lived_intermittent"): result["insufficient_scopes"].append({"flow_id":fid,"rule":rule,"reason_code":"timestamp_missing_or_invalid"})
            continue
        if iat.get("count", 0) >= minimum_iats and isinstance(cv, (int,float)) and cv <= periodic_cv:
            result["observations"].append(observation(flow,"periodicity_candidate",{"iat_count":iat["count"],"iat_cv":cv,"mean_iat_seconds":iat.get("mean")},{"min_iats":minimum_iats,"max_iat_cv":periodic_cv},["Statistical regularity is not an application or intent label."]))
        if flow.get("burst",{}).get("max_packets") is not None and flow["burst"]["max_packets"] >= burst_packets:
            result["observations"].append(observation(flow,"bursty_transfer",{"max_burst_packets":flow["burst"]["max_packets"]},{"min_burst_packets":burst_packets},["Bursting is a traffic pattern only."]))
        duration, idle = flow.get("duration_seconds"), iat.get("max")
        if isinstance(duration,(int,float)) and isinstance(idle,(int,float)) and duration >= long_seconds and idle >= idle_seconds:
            result["observations"].append(observation(flow,"long_lived_intermittent",{"duration_seconds":duration,"max_iat_seconds":idle},{"min_duration_seconds":long_seconds,"min_idle_seconds":idle_seconds},["No endpoint role or application identity was inferred."]))
    if not source["flows"]: result["status"]="empty"
    elif result["insufficient_scopes"]: result["status"]="partial" if result["observations"] else "insufficient_evidence"
    result["metrics"]["observation_count"]=len(result["observations"])
    output_dir.mkdir(parents=True); (output_dir/"behaviors.json").write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    return result
def main(argv: list[str]|None=None)->int:
    p=argparse.ArgumentParser(description="Derive non-semantic M10 traffic-pattern observations."); p.add_argument("input",type=Path); p.add_argument("--output-dir",required=True,type=Path); a=p.parse_args(argv)
    try: analyze(a.input,a.output_dir)
    except (ValueError,FileExistsError,OSError) as exc: print(f"m10: {exc}",file=sys.stderr); return 2
    print(a.output_dir/"behaviors.json"); return 0
if __name__=="__main__": raise SystemExit(main())

