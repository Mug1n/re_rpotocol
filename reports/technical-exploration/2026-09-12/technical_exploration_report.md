# 技术探索题专项演示结果

## 输入

- 未知 DAT：`data\external\raw\watchpat\testdata.dat`（SHA-256：`a3503a1b55c0cb67507bf28b552b2006f7ec8eb2f007c646723e3207c76426cc`）
- 恢复输入：`experiments\M08\fixtures\nested-base64-gzip.dat`（SHA-256：`77047b489fcdc676407303b859199b4401e8def876b8b2bdd0997b522cbbb5c6`）

## 未知 DAT 分析

已运行 M01--M06 与 M12：内容探测、特征、自动分帧、聚类、对齐、字段候选和证据报告。边界、类型组与字段均是可审计候选，不是协议语义真值。

## 数据恢复

M08 状态：`ok`；恢复候选数：4。
仅记录通过 UTF-8/UTF-16、Hex、Base64、gzip/zlib 完整性验证的恢复链。TLS/SSH 等加密内容若没有显式解密材料，会被标记为不可恢复，而不是伪造明文。

## 抓包协议与访问行为

抓包状态：`complete`。
已运行 M01、M02、M07、M09、M10 与 M12；M07 只使用 TShark 实际可见的标准协议字段，M09/M10 只报告流量统计和行为候选。

## 大模型边界

若使用 `--invoke-model` 且进程显式提供 `DEEPSEEK_API_KEY`，模型只能基于 M12 的哈希绑定证据生成带引用说明；模型不会替代协议解析、解密或真值评分。
