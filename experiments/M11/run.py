#!/usr/bin/env python3
"""M11 conditional grouped classifier. It never treats clusters as labels."""
from __future__ import annotations
import argparse, hashlib, json, sys
from collections import Counter
from pathlib import Path
from typing import Any

VERSION="0.1"
def sha(path:Path)->str:return hashlib.sha256(path.read_bytes()).hexdigest()
def load(path:Path)->dict[str,Any]:
    try: data=json.loads(path.read_text(encoding="utf-8"))
    except (OSError,json.JSONDecodeError) as exc:raise ValueError(f"invalid feature dataset: {exc}") from exc
    if not isinstance(data,dict) or data.get("schema_version")!=VERSION or not isinstance(data.get("rows"),list):raise ValueError("expected a version 0.1 dataset with rows")
    return data
def base(source_path:Path,data:dict[str,Any],task:str,status:str,reason:str|None=None)->dict[str,Any]:
    task_info={"label_dimension":task,"classes":[],"unknown_rejection":"not implemented; no unsupported labels are predicted","feature_schema_version":data.get("feature_definition_version",VERSION)}
    out={"schema_version":VERSION,"source":{"module":"M09-compatible-feature-rows","artifact_path":str(source_path),"artifact_sha256":sha(source_path),"record_count":len(data["rows"])},"status":status,"parameters":{"algorithm":"random_forest","random_seed":17,"split_strategy":"grouped_holdout","test_fraction":0.25},"task":task_info,"split":{"group_key":"group_id","train_count":0,"test_count":0,"group_overlap":[],"random_seed":17},"model":None,"metrics":None,"predictions":[],"leakage_checks":{"groups_disjoint":True,"preprocessing_fit_scope":"training_only when a model is trained","cluster_id_not_used_as_label":True},"warnings":[]}
    if reason:out["warnings"].append(reason)
    return out
def analyze(input_path:Path,output_dir:Path,*,task:str)->dict[str,Any]:
    if output_dir.exists():raise FileExistsError(f"output directory already exists: {output_dir}")
    data=load(input_path)
    result=base(input_path,data,task,"empty" if not data["rows"] else "insufficient_labels")
    valid=[]
    for row in data["rows"]:
        if not isinstance(row,dict):continue
        label=(row.get("labels") or {}).get(task)
        features=row.get("features")
        if label is not None and isinstance(features,dict) and row.get("group_id") is not None: valid.append(row)
    labels=Counter(str(row["labels"][task]) for row in valid)
    groups={str(row["group_id"]) for row in valid}
    result["task"]["classes"]=sorted(labels)
    if not valid: result["warnings"].append("No explicit labels with group_id and fixed feature rows were supplied.")
    elif len(labels)<2: result["warnings"].append("At least two explicit label classes are required; no accuracy was calculated.")
    elif len(groups)<2: result["warnings"].append("At least two groups are required for a leakage-resistant split.")
    else:
        # sklearn remains optional: no dependency means an honest, useful artifact rather than a fake score.
        try:
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.model_selection import GroupShuffleSplit
            from sklearn.metrics import classification_report, confusion_matrix, f1_score
        except ImportError:
            result["status"]="dependency_unavailable";result["warnings"].append("scikit-learn is unavailable; no model or metrics were produced.")
        else:
            names=sorted(valid[0]["features"])
            if any(sorted(row["features"])!=names or any(not isinstance(row["features"][name],(int,float)) for name in names) for row in valid):
                result["warnings"].append("Rows do not share one finite fixed feature definition.")
            else:
                splitter=GroupShuffleSplit(n_splits=1,test_size=.25,random_state=17)
                indices=list(splitter.split(valid,groups=[str(row["group_id"]) for row in valid]))
                if not indices: result["warnings"].append("Unable to create grouped split.")
                else:
                    train,test=indices[0]; train_groups={str(valid[i]["group_id"]) for i in train}; test_groups={str(valid[i]["group_id"]) for i in test}
                    if len(train) == 0 or len(test) == 0 or train_groups & test_groups: raise ValueError("invalid grouped split")
                    x=[[row["features"][name] for name in names] for row in valid]; y=[str(row["labels"][task]) for row in valid]
                    model=RandomForestClassifier(n_estimators=100,random_state=17,n_jobs=1);model.fit([x[i] for i in train],[y[i] for i in train]); pred=model.predict([x[i] for i in test])
                    classes=sorted(labels); report=classification_report([y[i] for i in test],pred,labels=classes,output_dict=True,zero_division=0)
                    result["status"]="ok";result["split"]={"group_key":"group_id","train_count":len(train),"test_count":len(test),"group_overlap":[],"random_seed":17};result["model"]={"algorithm":"RandomForestClassifier","parameters":{"n_estimators":100,"random_state":17},"feature_names":names};result["metrics"]={"macro_f1":f1_score([y[i] for i in test],pred,labels=classes,average="macro",zero_division=0),"per_class":report,"confusion_matrix":{"labels":classes,"values":confusion_matrix([y[i] for i in test],pred,labels=classes).tolist()}};result["predictions"]=[{"scope_id":valid[i].get("id"),"predicted_label":str(label),"score_type":"class_probability","score":float(max(prob)),"rejected":False} for i,label,prob in zip(test,pred,model.predict_proba([x[i] for i in test]))]
    output_dir.mkdir(parents=True);(output_dir/"classification.json").write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n",encoding="utf-8");return result
def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description="Train M11 only when explicit grouped labels are valid.");p.add_argument("input",type=Path);p.add_argument("--task",required=True);p.add_argument("--output-dir",required=True,type=Path);a=p.parse_args(argv)
    try:analyze(a.input,a.output_dir,task=a.task)
    except (ValueError,FileExistsError,OSError) as exc:print(f"m11: {exc}",file=sys.stderr);return 2
    print(a.output_dir/"classification.json");return 0
if __name__=="__main__":raise SystemExit(main())

