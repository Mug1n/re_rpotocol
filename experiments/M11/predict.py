#!/usr/bin/env python3
"""Run a verified M11 model on label-free fixed-version feature rows."""
from __future__ import annotations
import argparse, hashlib, json, math
from pathlib import Path

def sha(path: Path) -> str: return hashlib.sha256(path.read_bytes()).hexdigest()
def predict(classification: Path, rows_path: Path, output: Path) -> dict:
 if output.exists(): raise FileExistsError(f"output already exists: {output}")
 result=json.loads(classification.read_text(encoding="utf-8")); rows=json.loads(rows_path.read_text(encoding="utf-8"))
 model_info=result.get("model") or {}; artifact=model_info.get("artifact") or {}
 model_path=classification.parent/artifact.get("artifact_ref","")
 if not model_path.is_file() or sha(model_path)!=artifact.get("sha256"): raise ValueError("model artifact is missing or its hash does not match classification.json")
 if rows.get("feature_definition_version")!=result.get("task",{}).get("feature_schema_version"): raise ValueError("feature definition version mismatch")
 names=model_info.get("feature_names");
 if not isinstance(names,list) or not names: raise ValueError("classification has no fixed model feature names")
 import joblib
 model=joblib.load(model_path); predictions=[]
 for row in rows.get("rows",[]):
  features=row.get("features",{})
  if set(features)!=set(names) or any(not isinstance(features[n],(int,float)) or not math.isfinite(float(features[n])) for n in names): raise ValueError(f"invalid features for {row.get('id')}")
  vector=[[float(features[n]) for n in names]]; label=str(model.predict(vector)[0]); score=float(max(model.predict_proba(vector)[0]))
  predictions.append({"scope_id":row.get("id"),"predicted_label":label,"score_type":"class_probability","score":score,"rejected":False})
 out={"schema_version":"0.1","source":{"classification_path":str(classification),"classification_sha256":sha(classification),"rows_path":str(rows_path),"rows_sha256":sha(rows_path)},"model":{"artifact_ref":artifact["artifact_ref"],"sha256":artifact["sha256"],"feature_definition_version":rows["feature_definition_version"]},"predictions":predictions,"warnings":["Predictions are model outputs for new inputs and do not assert ground truth."]}
 output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(out,ensure_ascii=False,indent=2)+"\n",encoding="utf-8");return out
def main(argv=None):
 p=argparse.ArgumentParser();p.add_argument("classification",type=Path);p.add_argument("rows",type=Path);p.add_argument("--output",required=True,type=Path);a=p.parse_args(argv);predict(a.classification,a.rows,a.output);print(a.output)
if __name__=="__main__":main()
