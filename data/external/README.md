# 外部真实 DAT 样本

本目录只保存来源、许可、提交版本和哈希均已核实的小型公开样本。`raw/` 中的文件保持原始字节，不得覆盖或直接修改；派生样本应另存到 `data/derived/` 并在 manifest 中记录父文件及变换。

当前包含：

- `raw/audiobeat-octapro/dsp_m2.dat`：Audiobeat OctaPro 8.2 车载 DSP 应用导出的 US002 二进制预设。适合 M01–M06、M08；不含网络时间与方向元数据。
- `raw/watchpat/testdata.dat`：WatchPAT ONE BLE 客户端仓库发布的 15 条长度前缀 DATA_PACKET 记录。适合 M01–M03、M05–M06、M08；文件不保留 BLE 链路层包边界，但应用包内含协议头、时间戳和 CRC。

WatchPAT 样本包含生理传感器数据，虽然已经公开发布且未发现姓名、设备序列号或 BLE 地址字段，本项目仍只将其用于离线协议结构测试，不用于个人识别、医学判断或对外再发布。

精确来源、提交、哈希和使用限制见 `manifest.json`；许可证原文位于 `licenses/`。
