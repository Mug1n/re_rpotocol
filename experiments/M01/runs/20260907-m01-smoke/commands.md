# M1 冒烟与边界测试命令

工作目录：`D:\协议逆向`

## 版本与依赖

```powershell
& 'C:\Program Files\Wireshark\tshark.exe' --version
& 'experiments\M01\.venv\Scripts\python.exe' -m pip install scapy==2.7.0 dpkt==1.9.8 pyshark==0.6
```

## 生成可追溯 fixture

```powershell
& 'C:\Program Files\Wireshark\text2pcap.exe' -D -4 192.0.2.10,192.0.2.20 -T 40000,9000 data\fixtures\m01-stream-a.txt data\fixtures\m01-stream-a.pcapng
& 'C:\Program Files\Wireshark\text2pcap.exe' -D -F pcap -4 198.51.100.10,198.51.100.20 -T 41000,9001 data\fixtures\m01-stream-b.txt data\fixtures\m01-stream-b.pcap
& 'C:\Program Files\Wireshark\mergecap.exe' -F pcapng -w data\fixtures\m01-multi-flow.pcapng data\fixtures\m01-stream-a.pcapng data\fixtures\m01-stream-b.pcap
& 'C:\Program Files\Wireshark\editcap.exe' -F pcapng -s 50 data\fixtures\m01-multi-flow.pcapng data\fixtures\m01-truncated.pcapng
```

乱序与重复段 fixture 由 Scapy 2.7.0 构造，固定客户端序列号 1000、服务端序列号 5000；数据段到达顺序为 `HELLO`、`!`、` WORLD`、重复的 ` WORLD`。Scapy 的 `wrpcap` 初始写出 PCAP，随后使用 `editcap -F pcapng` 转换，并由 `capinfos` 验证实际容器格式。

## TShark 字段与重组

```powershell
& 'C:\Program Files\Wireshark\tshark.exe' -r data\fixtures\m01-multi-flow.pcapng -T fields -e frame.number -e frame.time_epoch -e frame.interface_id -e tcp.stream -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.seq -e tcp.len -e tcp.payload
& 'C:\Program Files\Wireshark\tshark.exe' -r data\fixtures\m01-multi-flow.pcapng -q -z follow,tcp,hex,0
& 'C:\Program Files\Wireshark\tshark.exe' -r data\fixtures\m01-multi-flow.pcapng -q -z follow,tcp,hex,1
& 'C:\Program Files\Wireshark\tshark.exe' -r data\fixtures\m01-reassembly.pcapng -q -z follow,tcp,hex,0
```

## Python 候选

```powershell
& 'experiments\M01\.venv\Scripts\python.exe' -c "from scapy.all import rdpcap; print(len(rdpcap(r'data\fixtures\m01-multi-flow.pcapng')))"
& 'experiments\M01\.venv\Scripts\python.exe' -c "import dpkt; f=open(r'data\fixtures\m01-multi-flow.pcapng','rb'); print([str(ts) for ts,_ in dpkt.pcapng.Reader(f)])"
```
