# 协议与流量分析报告

## 观测事实

- [evidence-m01-33abe24df5cbad28] Input format=pcapng, status=ok, length=1844 bytes.
- [evidence-m02-6889fe7f6da94ab4] Byte features: length=353, entropy=5.172581540179328 bits/byte, printable_ascii_ratio=0.9546742209631728, zero_ratio=0.0.
- [evidence-m03-75bf176b1f2f2ec8] Byte range [303, 353) was not framed; length=50 bytes, reason=not_accepted_by_rule.
- [evidence-m03-983eed50ba2583d1] Message download-01-d8f9c37a5714-tcp-0-node1_to_node0-38c0c8258fcb-message-000001 framed by fixed rule at byte range [101, 202); length=101 bytes.
- [evidence-m03-abdedcc38dd9e195] Message download-01-d8f9c37a5714-tcp-0-node1_to_node0-38c0c8258fcb-message-000000 framed by fixed rule at byte range [0, 101); length=101 bytes.
- [evidence-m03-f4e08550b0a4efca] Message download-01-d8f9c37a5714-tcp-0-node1_to_node0-38c0c8258fcb-message-000002 framed by fixed rule at byte range [202, 303); length=101 bytes.
- [evidence-m04-29bdcd9d097cd176] Message download-01-d8f9c37a5714-tcp-0-node1_to_node0-38c0c8258fcb-message-000001 was classified as clustering noise.
- [evidence-m04-7fa738a149383a20] Message download-01-d8f9c37a5714-tcp-0-node1_to_node0-38c0c8258fcb-message-000000 was classified as clustering noise.
- [evidence-m04-e3fa3f8d4f634e56] Message download-01-d8f9c37a5714-tcp-0-node1_to_node0-38c0c8258fcb-message-000002 was classified as clustering noise.
- [evidence-m05-1ebc1841c3406ec1] Message download-01-d8f9c37a5714-tcp-0-node1_to_node0-38c0c8258fcb-message-000001 was not aligned: m04_noise.
- [evidence-m05-7622460bef761315] Message download-01-d8f9c37a5714-tcp-0-node1_to_node0-38c0c8258fcb-message-000002 was not aligned: m04_noise.
- [evidence-m05-9a6d67d85236b5af] Message download-01-d8f9c37a5714-tcp-0-node1_to_node0-38c0c8258fcb-message-000000 was not aligned: m04_noise.
- [evidence-m06-55c2bb6a3b3fd119] M06 artifact status=empty.
- [evidence-m07-17508147355916ad] Protocol http observed with visibility=application_visible; http.request.method=GET, http.host=127.0.0.1:18080, http.request.uri=/download.
- [evidence-m07-d837db017019d85d] Protocol http observed with visibility=application_visible; http.request.uri=/download, http.response.code=200, http.content_type=text/plain; charset=utf-8.
- [evidence-m08-843722a5fadbe7b4] Recovered 101 bytes via utf8; completeness=candidate.
- [evidence-m09-2c7a111907a1d04b] Flow download-01-d8f9c37a5714-tcp-flow-0: 13 packets, 1076 bytes, duration=0.0106697 seconds.
- [evidence-m10-027ffd5981f90765] Traffic pattern bursty_transfer observed for flow download-01-d8f9c37a5714-tcp-flow-0; values={"max_burst_packets":13}; thresholds={"min_burst_packets":3}.
- [evidence-m11-17069fae633fd52b] Evaluation prediction for download-05-230e4abd0f69-tcp-flow-0: label=download, score=0.97, rejected=False.
- [evidence-m11-71dbaaa88f28d15c] Evaluation prediction for download-03-ddfc5a5dc1d4-tcp-flow-0: label=download, score=0.92, rejected=False.
- [evidence-m11-b5b3eb2fdaf7bd96] Evaluation prediction for periodic-02-7e496d2d9050-tcp-flow-0: label=periodic, score=0.99, rejected=False.
- [evidence-m11-cdb2978e3d53a92a] Evaluation prediction for upload-06-ccbfdfa0eee3-tcp-flow-0: label=upload, score=0.96, rejected=False.
- [evidence-m11-ebd82a86598c50cf] Evaluation prediction for periodic-03-3c4913b0e1ee-tcp-flow-0: label=periodic, score=0.99, rejected=False.

## 解释与假设

- 未生成解释假设；确定性证据保持权威。

## 无法判断

- [evidence-m01-33abe24df5cbad28] TShark did not populate frame.file_off; packet source offsets are null.
- [evidence-m02-6889fe7f6da94ab4] Entropy alone cannot distinguish encryption, compression, and random data.
- [evidence-m03-75bf176b1f2f2ec8] not_accepted_by_rule
- [evidence-m03-983eed50ba2583d1] A configured framing rule is a hypothesis; accepted boundaries are not protocol truth.
- [evidence-m03-abdedcc38dd9e195] A configured framing rule is a hypothesis; accepted boundaries are not protocol truth.
- [evidence-m03-f4e08550b0a4efca] A configured framing rule is a hypothesis; accepted boundaries are not protocol truth.
- [evidence-m04-29bdcd9d097cd176] No non-noise cluster assignment was available.
- [evidence-m04-7fa738a149383a20] No non-noise cluster assignment was available.
- [evidence-m04-e3fa3f8d4f634e56] No non-noise cluster assignment was available.
- [evidence-m05-1ebc1841c3406ec1] m04_noise
- [evidence-m05-7622460bef761315] m04_noise
- [evidence-m05-9a6d67d85236b5af] m04_noise
- [evidence-m06-55c2bb6a3b3fd119] Field candidates are statistical runs, not confirmed protocol semantics.
- [evidence-m06-55c2bb6a3b3fd119] Length hypotheses require exact relations in the observed sample but may still be coincidental.
- [evidence-m06-55c2bb6a3b3fd119] Small clusters, low-quality M05 alignments, compression, or encryption can make boundaries unreliable.
- [evidence-m08-843722a5fadbe7b4] strict validation completed for every recorded transformation
- [evidence-m10-027ffd5981f90765] Bursting is a traffic pattern only.

## 后续建议

- 结合当前限制审阅证据，再决定是否追加人工或模型解释。
