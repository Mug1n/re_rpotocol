#!/usr/bin/env python3
"""Train/evaluate M11 on C1's explicit frozen partitions."""
import argparse,hashlib,json
from pathlib import Path
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report,confusion_matrix,f1_score
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('rows',type=Path);p.add_argument('--output-dir',required=True,type=Path);p.add_argument('--task',default='action_type');a=p.parse_args()
 if a.output_dir.exists():raise FileExistsError('output exists')
 d=json.loads(a.rows.read_text(encoding='utf-8-sig'));rows=d['rows']; names=sorted(rows[0]['features']); labels=sorted({r['labels'][a.task] for r in rows})
 parts={x:[r for r in rows if r['split']==x] for x in ('train','validation','test')}
 if any(not parts[x] or {r['labels'][a.task] for r in parts[x]}!=set(labels) for x in parts):raise ValueError('every frozen partition must contain every class')
 def xy(items):return [[r['features'][n] for n in names] for r in items],[r['labels'][a.task] for r in items]
 x,y=xy(parts['train']);model=RandomForestClassifier(n_estimators=200,random_state=17,n_jobs=1).fit(x,y)
 def score(items):
  x,y=xy(items);pred=model.predict(x);return {'macro_f1':f1_score(y,pred,labels=labels,average='macro',zero_division=0),'per_class':classification_report(y,pred,labels=labels,output_dict=True,zero_division=0),'confusion_matrix':{'labels':labels,'values':confusion_matrix(y,pred,labels=labels).tolist()},'majority_baseline':max(y.count(z) for z in labels)/len(y)}
 a.output_dir.mkdir(parents=True);mp=a.output_dir/'model.joblib';joblib.dump(model,mp);out={'schema_version':'0.1','task':a.task,'feature_definition_version':d['feature_definition_version'],'feature_names':names,'source_sha256':sha(a.rows),'model':{'artifact_ref':'model.joblib','sha256':sha(mp),'algorithm':'RandomForestClassifier','parameters':{'n_estimators':200,'random_state':17}},'partitions':{x:{'count':len(parts[x]),'groups':sorted(r['group_id'] for r in parts[x])} for x in parts},'validation':score(parts['validation']),'test':score(parts['test'])};(a.output_dir/'evaluation.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf8')
if __name__=='__main__':main()
