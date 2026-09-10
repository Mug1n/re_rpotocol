#!/usr/bin/env python3
"""Capture deterministic loopback acceptance samples and freeze isolated truth."""
from __future__ import annotations
import argparse, hashlib, http.client, json, subprocess, time, urllib.request
from pathlib import Path

def sha(data: bytes) -> str: return hashlib.sha256(data).hexdigest()
def request(base: str, action: str, upload: bytes) -> tuple[bytes, dict]:
 hostport=base.removeprefix("http://")
 if action == "upload":
  req=urllib.request.Request(base+"/upload",data=upload,method="POST"); body=urllib.request.urlopen(req,timeout=5).read(); return body,{"method":"POST","path":"/upload","uploaded_sha256":sha(upload)}
 if action == "periodic":
  conn=http.client.HTTPConnection(hostport,timeout=5); bodies=[]
  for _ in range(4):
   conn.request("GET","/periodic"); response=conn.getresponse(); bodies.append(response.read()); time.sleep(.25)
  conn.close(); return bodies[-1],{"method":"GET","path":"/periodic","requests_in_one_connection":4}
 return urllib.request.urlopen(base+"/download",timeout=5).read(),{"method":"GET","path":"/download"}
def capture(tshark: Path, interface: str, target: Path, base: str, action: str, upload: bytes) -> tuple[bytes,dict]:
 proc=subprocess.Popen([str(tshark),"-i",interface,"-f","tcp port "+base.rsplit(":",1)[1],"-w",str(target)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 try:
  time.sleep(.7); body,detail=request(base,action,upload); time.sleep(.7); return body,detail
 finally:
  proc.terminate()
  try: proc.wait(timeout=5)
  except subprocess.TimeoutExpired: proc.kill(); proc.wait()
def main(argv=None):
 p=argparse.ArgumentParser();p.add_argument("--base-url",default="http://127.0.0.1:18080");p.add_argument("--tshark",required=True,type=Path);p.add_argument("--interface",default="10");p.add_argument("--output-root",required=True,type=Path);a=p.parse_args(argv)
 if a.output_root.exists(): raise FileExistsError("output root already exists")
 captures=a.output_root/"captures";truth=a.output_root/"truth";captures.mkdir(parents=True);truth.mkdir()
 rows=[]; upload=b"acceptance-upload-v1"
 for action in ("download","upload","periodic"):
  for index in range(6):
   split=("train" if index<4 else "validation" if index==4 else "test"); ident=f"{action}-{index+1:02d}"; pcap=captures/f"{ident}.pcapng"
   body,detail=capture(a.tshark,a.interface,pcap,a.base_url,action,upload)
   truth_item={"sample_id":ident,"action":action,"response_sha256":sha(body),"response_length":len(body),**detail}
   truth_path=truth/f"{ident}.json";truth_path.write_text(json.dumps(truth_item,indent=2)+"\n",encoding="utf-8")
   rows.append({"sample_id":ident,"input_path":pcap.relative_to(a.output_root).as_posix(),"input_sha256":sha(pcap.read_bytes()),"source_type":"loopback_http_capture","task_id":ident,"group_id":ident,"split":split,"action":action,"truth_path":truth_path.relative_to(a.output_root).as_posix()})
 manifest={"schema_version":"0.1","generator":"capture_acceptance_samples.py","base_url":a.base_url,"tshark":str(a.tshark),"samples":rows,"warnings":["Truth files are isolated and must not be passed to analysis modules."]}
 (a.output_root/"manifest.json").write_text(json.dumps(manifest,indent=2)+"\n",encoding="utf-8")
if __name__=="__main__": main()
