from __future__ import annotations

import gzip
import hashlib
import http.client
import importlib.util
import io
import json
import sys
import tempfile
import threading
import unittest
import zlib
from contextlib import redirect_stderr
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[2]
M01_FIXTURE = ROOT / "experiments" / "tests" / "fixtures" / "contracts" / "m01-complete.json"
PAYLOAD_SCHEMA = ROOT / "research" / "M08-recovery" / "payload-sources.schema.json"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


PAYLOADS = load("acceptance_payload_sources", ROOT / "experiments" / "payload_sources.py")
SERVER = load("acceptance_http_server", ROOT / "scripts" / "acceptance_http_server.py")
M08 = load("acceptance_m08", ROOT / "experiments" / "M08" / "run.py")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class PayloadSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads(PAYLOAD_SCHEMA.read_text(encoding="utf-8"))

    def make_m01(self, root: Path, directions: list[tuple[str, bytes]], *, partial: bool = False) -> Path:
        artifact = json.loads(M01_FIXTURE.read_text(encoding="utf-8"))
        stream = artifact["streams"][0]
        stream["directions"] = []
        for direction, data in directions:
            target = root / f"{direction}.bin"
            target.write_bytes(data)
            stream["directions"].append({
                "direction": direction, "length": len(data),
                "sha256": digest(data), "artifact_ref": target.name,
            })
        if partial:
            stream["reassembly_status"] = "partial"
            stream["analysis"]["gap_or_loss_packets"] = 1
        path = root / "m01.json"
        path.write_text(json.dumps(artifact), encoding="utf-8")
        return path

    def test_all_directions_and_multiple_http_bodies_are_extracted(self):
        request = b"POST /upload HTTP/1.1\r\nHost: local\r\nContent-Length: 6\r\n\r\nUPLOAD"
        responses = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"5\r\nworld\r\n1\r\n!\r\n0\r\n\r\n"
        )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            m01 = self.make_m01(root, [("node0_to_node1", request), ("node1_to_node0", responses)])
            output = root / "payloads"
            result = PAYLOADS.extract_payload_sources(m01, output)
            jsonschema.validate(result, self.schema)
            self.assertEqual("ok", result["status"])
            self.assertEqual(3, result["metrics"]["payload_count"])
            self.assertEqual({"node0_to_node1", "node1_to_node0"}, {item["direction"] for item in result["sources"]})
            observed = [(output / item["output"]["artifact_ref"]).read_bytes() for item in result["sources"]]
            self.assertEqual([b"UPLOAD", b"hello", b"world!"], observed)
            for item, body in zip(result["sources"], observed):
                source_bytes = Path(item["source_artifact"]["artifact_path"]).read_bytes()
                rebuilt = b"".join(source_bytes[part["start"]:part["end"]] for part in item["source_ranges"])
                self.assertEqual(body, rebuilt)
                self.assertEqual(digest(body), item["output"]["sha256"])
            self.assertEqual(2, len(result["sources"][2]["source_ranges"]))

    def test_truncated_body_and_incomplete_transport_are_never_complete(self):
        truncated = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = PAYLOADS.extract_payload_sources(
                self.make_m01(root, [("node1_to_node0", truncated)], partial=True), root / "out"
            )
            self.assertEqual("partial", result["status"])
            self.assertEqual("partial", result["sources"][0]["completeness"])
            limitations = " ".join(result["sources"][0]["limitations"])
            self.assertIn("TRUNCATED_CONTENT_LENGTH_BODY", limitations)
            self.assertIn("incomplete transport", limitations)

    def test_non_http_and_tampered_stream_do_not_become_payloads(self):
        for invalid in (
            b"random bytes",
            b"GET missing-version\r\nContent-Length: 4\r\n\r\ndata",
            b"HTTP/not-a-version 200 OK\r\nContent-Length: 4\r\n\r\ndata",
        ):
            with self.subTest(invalid=invalid):
                with tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    m01 = self.make_m01(root, [("node0_to_node1", invalid)])
                    result = PAYLOADS.extract_payload_sources(m01, root / "out")
                    self.assertEqual("no_http_payloads", result["status"])
                    self.assertEqual([], result["sources"])
                    self.assertTrue(result["unparsed_ranges"])
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            m01 = self.make_m01(root, [("node0_to_node1", b"random bytes")])
            (root / "node0_to_node1.bin").write_bytes(b"tampered")
            output = root / "out"
            with self.assertRaisesRegex(ValueError, "(length|SHA-256) mismatch"):
                PAYLOADS.extract_payload_sources(m01, output)
            self.assertFalse(output.exists())

    def test_stream_budget_and_ambiguous_response_boundary_are_explicit(self):
        response = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nbody-without-length"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = PAYLOADS.extract_payload_sources(
                self.make_m01(root, [("node1_to_node0", response)]), root / "out",
                max_stream_bytes=len(response) - 1,
            )
            self.assertEqual([], result["sources"])
            self.assertEqual("STREAM_EXCEEDS_MAX_BYTES", result["unparsed_ranges"][0]["reason"])
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = PAYLOADS.extract_payload_sources(
                self.make_m01(root, [("node1_to_node0", response)]), root / "out"
            )
            self.assertEqual([], result["sources"])
            self.assertEqual("HTTP_BODY_BOUNDARY_UNAVAILABLE", result["unparsed_ranges"][0]["reason"])

    def test_invalid_chunk_stream_is_partial_not_complete(self):
        response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nabc"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = PAYLOADS.extract_payload_sources(
                self.make_m01(root, [("node1_to_node0", response)]), root / "out"
            )
            self.assertEqual("partial", result["status"])
            self.assertEqual("partial", result["sources"][0]["completeness"])
            self.assertIn("TRUNCATED_CHUNK_DATA", result["sources"][0]["limitations"])

    def test_protocol_declared_plaintext_and_gzip_recover_with_capture_provenance(self):
        truth = b"known recovered acceptance body\n"
        compressed = gzip.compress(truth, mtime=0)
        responses = (
            b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(truth)).encode() + b"\r\n\r\n" + truth
            + b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: "
            + str(len(compressed)).encode() + b"\r\n\r\n" + compressed
        )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            payload_dir = root / "payloads"
            manifest = PAYLOADS.extract_payload_sources(
                self.make_m01(root, [("node1_to_node0", responses)]), payload_dir
            )
            manifest_path = payload_dir / "payload_sources.json"
            plain = M08.analyze_payload_source(
                manifest_path, manifest["sources"][0]["source_id"], root / "plain-recovery"
            )
            plain_item = next(item for item in plain["recoveries"] if item["transformation_chain"][-1]["operation"] == "utf8")
            self.assertEqual("protocol_declared", plain_item["basis"])
            self.assertEqual("complete", plain_item["completeness"])
            self.assertEqual(manifest["sources"][0]["source_ranges"], plain_item["source_ranges"])
            self.assertEqual("node1_to_node0", plain_item["source_context"]["direction"])
            self.assertEqual(
                "strict_http_start_line_and_framing_headers",
                plain_item["source_context"]["recognition_basis"],
            )
            gzip_result = M08.analyze_payload_source(
                manifest_path, manifest["sources"][1]["source_id"], root / "gzip-recovery"
            )
            gzip_item = next(item for item in gzip_result["recoveries"] if [step["operation"] for step in item["transformation_chain"]] == ["gzip"])
            recovered = root / "gzip-recovery" / gzip_item["output"]["artifact_ref"]
            self.assertEqual(truth, recovered.read_bytes())
            self.assertEqual("protocol_declared", gzip_item["basis"])
            self.assertEqual("gzip", gzip_item["source_context"]["content_encoding"])

    def test_partial_payload_recovery_never_claims_complete(self):
        response = b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\npartial text"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            payload_dir = root / "payloads"
            manifest = PAYLOADS.extract_payload_sources(
                self.make_m01(root, [("node1_to_node0", response)]), payload_dir
            )
            result = M08.analyze_payload_source(
                payload_dir / "payload_sources.json", manifest["sources"][0]["source_id"], root / "recovery"
            )
            self.assertTrue(result["recoveries"])
            self.assertTrue(all(item["completeness"] == "partial" for item in result["recoveries"]))

    def test_payload_consumer_rejects_tampered_extracted_body(self):
        response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            payload_dir = root / "payloads"
            manifest = PAYLOADS.extract_payload_sources(
                self.make_m01(root, [("node1_to_node0", response)]), payload_dir
            )
            source = manifest["sources"][0]
            (payload_dir / source["output"]["artifact_ref"]).write_bytes(b"other")
            output = root / "recovery"
            with self.assertRaisesRegex(ValueError, "payload artifact (length|SHA-256) mismatch"):
                M08.analyze_payload_source(
                    payload_dir / "payload_sources.json", source["source_id"], output
                )
            self.assertFalse(output.exists())

    def test_payload_consumer_rejects_tampered_m01_parent(self):
        response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            payload_dir = root / "payloads"
            m01 = self.make_m01(root, [("node1_to_node0", response)])
            manifest = PAYLOADS.extract_payload_sources(m01, payload_dir)
            m01.write_text(m01.read_text(encoding="utf-8") + " ", encoding="utf-8")
            output = root / "recovery"
            with self.assertRaisesRegex(ValueError, "artifact SHA-256 mismatch"):
                M08.analyze_payload_source(
                    payload_dir / "payload_sources.json", manifest["sources"][0]["source_id"], output
                )
            self.assertFalse(output.exists())

    def test_unsupported_brotli_is_explicitly_skipped(self):
        response = b"HTTP/1.1 200 OK\r\nContent-Encoding: br\r\nContent-Length: 6\r\n\r\nopaque"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            payload_dir = root / "payloads"
            manifest = PAYLOADS.extract_payload_sources(
                self.make_m01(root, [("node1_to_node0", response)]), payload_dir
            )
            result = M08.analyze_payload_source(
                payload_dir / "payload_sources.json", manifest["sources"][0]["source_id"], root / "recovery"
            )
            self.assertEqual([], result["recoveries"])
            self.assertEqual("UNSUPPORTED_CONTENT_ENCODING", result["skipped_sources"][0]["reason_code"])
            self.assertEqual("br", result["skipped_sources"][0]["source_context"]["content_encoding"])

    def test_m08_cli_rejects_mixed_source_modes_without_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            direct = root / "direct.bin"
            direct.write_bytes(b"plain")
            output = root / "recovery"
            with redirect_stderr(io.StringIO()):
                status = M08.main([
                    str(direct), "--payload-sources", str(root / "sources.json"),
                    "--payload-source-id", "http-0", "--output-dir", str(output),
                ])
            self.assertEqual(2, status)
            self.assertFalse(output.exists())

    def test_m08_cli_requires_payload_source_id_without_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "recovery"
            with redirect_stderr(io.StringIO()):
                status = M08.main([
                    "--payload-sources", str(root / "sources.json"),
                    "--output-dir", str(output),
                ])
            self.assertEqual(2, status)
            self.assertFalse(output.exists())


class AcceptanceServerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.record_dir = Path(self.temporary.name) / "uploads"
        self.server = SERVER.create_server("127.0.0.1", 0, record_dir=self.record_dir)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop)
        self.host, self.port = self.server.server_address[:2]

    def _stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, method: str, path: str, body: bytes | None = None):
        connection = http.client.HTTPConnection(self.host, self.port, timeout=2)
        try:
            connection.request(method, path, body=body)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_fixed_chunked_and_compressed_endpoints_have_known_truth(self):
        status, _, body = self.request("GET", "/download")
        self.assertEqual(200, status)
        self.assertEqual(SERVER.DOWNLOAD_BODY, body)
        status, headers, body = self.request("GET", "/chunked")
        self.assertEqual(200, status)
        self.assertEqual("chunked", headers["Transfer-Encoding"])
        self.assertEqual(SERVER.CHUNKED_BODY, body)
        _, _, compressed = self.request("GET", "/gzip")
        self.assertEqual(SERVER.DOWNLOAD_BODY, gzip.decompress(compressed))
        _, _, compressed = self.request("GET", "/zlib")
        self.assertEqual(SERVER.DOWNLOAD_BODY, zlib.decompress(compressed))

    def test_upload_is_hashed_and_optionally_recorded(self):
        upload = b"known upload truth\x00\xff"
        status, _, response = self.request("POST", "/upload", upload)
        self.assertEqual(200, status)
        value = json.loads(response)
        self.assertEqual({"length": len(upload), "sha256": digest(upload)}, value)
        self.assertEqual(upload, (self.record_dir / f"upload-{digest(upload)}.bin").read_bytes())

    def test_upload_limit_is_enforced(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.server = SERVER.create_server("127.0.0.1", 0, max_upload_bytes=3)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address[:2]
        status, _, _ = self.request("POST", "/upload", b"four")
        self.assertEqual(413, status)

    def test_service_rejects_non_loopback_binding(self):
        with self.assertRaisesRegex(ValueError, "loopback"):
            SERVER.create_server("0.0.0.0", 0)


if __name__ == "__main__":
    unittest.main()
