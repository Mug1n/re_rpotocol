# 运行环境

记录日期：2026-09-07  
工作目录：`D:\协议逆向`

## 已核实

| 项目 | 结果 | 备注 |
|---|---|---|
| 操作系统 | Microsoft Windows 10.0.26200.9168 | 由 `cmd /c ver` 获取 |
| 系统 Python | 3.14.5 | `python` / `py` |
| Codex 捆绑 Python | 3.12.14 | 可用于隔离的调研脚本 |
| pip | 26.1.1 | 绑定系统 Python 3.14 |
| Git | 2.54.0.windows.1 | 当前目录不是 Git 仓库 |
| tshark | 已安装，未加入 PATH | `C:\Program Files\Wireshark\tshark.exe` |
| uv | 未发现 | 后续可按实际依赖决定是否安装 |
| GPU | NVIDIA GeForce RTX 4060 Laptop GPU | 驱动 581.42，显存 8188 MiB |

## M1 隔离环境

位置：`experiments/M01/.venv`

| 包 / 工具 | 版本 |
|---|---|
| Python | 3.12.14 |
| TShark / text2pcap / capinfos | 4.6.6 |
| Scapy | 2.7.0 |
| dpkt | 1.9.8 |
| PyShark | 0.6 |
| jsonschema | 4.25.1 |

首次 pip 请求在默认沙箱内被 WinError 10013 拦截；获准外网后通过阿里云 PyPI 镜像安装成功。

## 待核实

- Wireshark/tshark 的完整版本、插件与可用 dissector。
- 各模块依赖与 Python 3.12/3.14 兼容性。
- CPU、可用内存、磁盘空间和实验资源基线。
- 外部网络、模型凭据以及可用数据集。
