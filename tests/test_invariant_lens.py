"""Deterministic and consensus-boundary tests for InvariantLens."""
import base64
import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest
from urllib.parse import unquote, urlsplit


OWNER = "0x1111111111111111111111111111111111111111"
AUDITOR = "0x2222222222222222222222222222222222222222"
SHA = "a" * 40
OTHER_SHA = "b" * 40


class UserError(Exception):
    pass


class ConsensusDisagreement(Exception):
    pass


class Return:
    def __init__(self, calldata):
        self.calldata = calldata


class Address:
    def __init__(self, value):
        self.as_hex = value.lower()


class Runtime:
    def __init__(self):
        self.sender = Address(OWNER)
        self.files = {
            "contracts/example.py": "def privileged_write(sender, owner):\n    assert sender == owner\n    return True\n",
            "README.md": "# Example\nAll privileged writes check the sender.\n",
        }
        self.statuses = {}
        self.response_ref = SHA
        self.response_path_override = None
        self.prompt_results = []
        self.prompts = []
        self.web_requests = []

    def web_request(self, url, method="GET"):
        self.web_requests.append((url, method))
        marker = "/contents/"
        path = unquote(urlsplit(url).path.split(marker, 1)[1])
        status = self.statuses.get(path, 200)
        if status != 200:
            return types.SimpleNamespace(status_code=status, body=b'{"message":"error"}')
        content = self.files.get(path, "")
        canonical_path = self.response_path_override or path
        payload = {
            "type": "file",
            "encoding": "base64",
            "content": base64.b64encode(content.encode()).decode(),
            "html_url": f"https://github.com/example/repo/blob/{self.response_ref}/{canonical_path}",
        }
        return types.SimpleNamespace(status_code=200, body=json.dumps(payload).encode())

    def exec_prompt(self, prompt, response_format=None):
        self.prompts.append(prompt)
        if response_format != "json":
            raise AssertionError("contract must request JSON")
        if not self.prompt_results:
            raise AssertionError("missing prompt result")
        return self.prompt_results.pop(0)

    def run_nondet_unsafe(self, leader_fn, validator_fn):
        leader = leader_fn()
        if not validator_fn(Return(leader)):
            raise ConsensusDisagreement("validator rejected leader report")
        return leader


def load_contract(runtime):
    module = types.ModuleType("genlayer")

    class Public:
        @staticmethod
        def write(fn):
            return fn

        @staticmethod
        def view(fn):
            return fn

    class Contract:
        pass

    class U32(int):
        pass

    class TreeMap(dict):
        @classmethod
        def __class_getitem__(cls, _item):
            return cls

    gl = types.SimpleNamespace(
        Contract=Contract,
        public=Public(),
        message=types.SimpleNamespace(sender_address=runtime.sender),
        message_raw={"datetime": "2026-10-31T08:00:00+00:00"},
        nondet=types.SimpleNamespace(
            web=types.SimpleNamespace(request=runtime.web_request),
            exec_prompt=runtime.exec_prompt,
        ),
        vm=types.SimpleNamespace(
            UserError=UserError,
            Return=Return,
            run_nondet_unsafe=runtime.run_nondet_unsafe,
        ),
    )
    module.gl = gl
    module.u32 = U32
    module.TreeMap = TreeMap
    module.Address = Address
    module.__all__ = ["gl", "u32", "TreeMap", "Address"]
    sys.modules["genlayer"] = module
    path = Path(__file__).parents[1] / "contracts" / "invariant_lens.py"
    spec = importlib.util.spec_from_file_location("invariant_lens_under_test", path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded, gl


def citation(file_index=0, start=2, end=2, quote="    assert sender == owner"):
    return {"file_index": file_index, "start_line": start, "end_line": end, "quote": quote}


def report(statuses=("PASS",), coverage=900, citations=True):
    rows = []
    for idx, status in enumerate(statuses):
        rows.append({
            "invariant_index": idx,
            "status": status,
            "citations": [citation()] if citations and status != "UNKNOWN" else [],
            "reason": "The cited authorization check supports this conclusion.",
            "counterexample": "Searched for an unguarded privileged path; none was found.",
            "coverage_milli": coverage if status != "UNKNOWN" else 0,
        })
    return {"reports": rows, "summary": "Proof-carrying compliance report."}


def validator_accept(statuses=("PASS",)):
    return {"valid": True, "status_vector": list(statuses), "reason": "Citations and conclusions are supported."}


class InvariantLensTests(unittest.TestCase):
    def setUp(self):
        self.runtime = Runtime()
        self.module, self.gl = load_contract(self.runtime)
        self.contract = self.module.InvariantLens()
        self.contract.policies_json = {}
        self.contract.audits_json = {}
        self.contract.dedupe_ids = {}

    def set_sender(self, value):
        self.runtime.sender = Address(value)
        self.gl.message.sender_address = self.runtime.sender

    def create_policy(self, invariants=None):
        invariants = invariants or ["Every privileged write requires sender authorization."]
        return self.contract.create_policy(
            "Authorization policy", "Reusable source-code security invariants.", json.dumps(invariants)
        )

    def manifest(self, paths=("contracts/example.py",)):
        return json.dumps([f"https://github.com/example/repo/blob/{SHA}/{path}" for path in paths])

    def run_audit(self, leader=None, validator=None, policy_id=None, paths=("contracts/example.py",)):
        policy_id = policy_id or self.create_policy()
        self.set_sender(AUDITOR)
        self.runtime.prompt_results = [leader or report(), validator or validator_accept()]
        audit_id = self.contract.audit(policy_id, self.manifest(paths), SHA)
        return self.contract.get_audit(audit_id)

    def test_policy_is_content_addressed_and_owner_recorded(self):
        policy_id = self.create_policy()
        policy = self.contract.get_policy(policy_id)
        self.assertEqual(policy["owner"], OWNER)
        self.assertEqual(len(policy["policy_hash"]), 64)
        self.assertEqual(self.contract.get_policy_count(), 1)

    def test_policy_input_validation(self):
        bad_values = ["not json", "{}", "[]", json.dumps(["x"] * 9)]
        for raw in bad_values:
            with self.subTest(raw=raw), self.assertRaises(UserError):
                self.contract.create_policy("P", "D", raw)
        with self.assertRaises(UserError):
            self.contract.create_policy("", "D", '["x"]')
        with self.assertRaises(UserError):
            self.contract.create_policy("P", "", '["x"]')

    def test_policy_invariant_length_and_control_characters(self):
        with self.assertRaises(UserError):
            self.contract.create_policy("P", "D", json.dumps(["x" * 501]))
        with self.assertRaises(UserError):
            self.contract.create_policy("P\u0001", "D", '["x"]')

    def test_verified_audit_records_proof_and_requester(self):
        audit = self.run_audit()
        self.assertEqual(audit["outcome"], "VERIFIED")
        self.assertEqual(audit["requester"], AUDITOR)
        self.assertEqual(audit["commit_sha"], SHA)
        self.assertEqual(audit["reports"][0]["status"], "PASS")
        self.assertEqual(self.contract.get_audit_count(), 1)

    def test_violation_is_derived_from_any_fail(self):
        invariants = ["Authorization is required.", "No unsafe path exists."]
        pid = self.create_policy(invariants)
        leader = report(("PASS", "FAIL"))
        validator = validator_accept(("PASS", "FAIL"))
        audit = self.run_audit(leader, validator, pid)
        self.assertEqual(audit["outcome"], "VIOLATION")

    def test_unknown_prevents_verified(self):
        invariants = ["Authorization is required.", "All branches are safe."]
        pid = self.create_policy(invariants)
        leader = report(("PASS", "UNKNOWN"))
        validator = validator_accept(("PASS", "UNKNOWN"))
        audit = self.run_audit(leader, validator, pid)
        self.assertEqual(audit["outcome"], "INCONCLUSIVE")

    def test_mutable_and_non_file_urls_are_rejected(self):
        pid = self.create_policy()
        urls = [
            "https://github.com/example/repo",
            "https://github.com/example/repo/pull/1",
            "https://github.com/example/repo/blob/main/README.md",
            "https://example.com/file.py",
        ]
        for url in urls:
            with self.subTest(url=url), self.assertRaises(UserError):
                self.contract.audit(pid, json.dumps([url]), SHA)

    def test_url_sha_mismatch_is_rejected(self):
        pid = self.create_policy()
        url = f"https://github.com/example/repo/blob/{OTHER_SHA}/README.md"
        with self.assertRaisesRegex(UserError, "URL ref must match"):
            self.contract.audit(pid, json.dumps([url]), SHA)

    def test_raw_github_url_is_supported(self):
        pid = self.create_policy()
        self.runtime.prompt_results = [report(), validator_accept()]
        raw = f"https://raw.githubusercontent.com/example/repo/{SHA}/contracts/example.py"
        self.contract.audit(pid, json.dumps([raw]), SHA)
        self.assertIn(f"?ref={SHA}", self.runtime.web_requests[0][0])

    def test_url_credentials_query_fragment_and_port_are_rejected(self):
        pid = self.create_policy()
        variants = [
            f"https://user:pw@github.com/example/repo/blob/{SHA}/README.md",
            f"https://github.com/example/repo/blob/{SHA}/README.md?plain=1",
            f"https://github.com/example/repo/blob/{SHA}/README.md#L1",
            f"https://github.com:8443/example/repo/blob/{SHA}/README.md",
        ]
        for url in variants:
            with self.subTest(url=url), self.assertRaises(UserError):
                self.contract.audit(pid, json.dumps([url]), SHA)

    def test_short_missing_and_nonhex_sha_are_rejected(self):
        pid = self.create_policy()
        for sha in ("", "abc123", "z" * 40):
            with self.subTest(sha=sha), self.assertRaises(UserError):
                self.contract.audit(pid, self.manifest(), sha)

    def test_duplicate_and_oversized_manifest_are_rejected(self):
        pid = self.create_policy()
        one = f"https://github.com/example/repo/blob/{SHA}/README.md"
        with self.assertRaisesRegex(UserError, "duplicate"):
            self.contract.audit(pid, json.dumps([one, one]), SHA)
        many = [f"https://github.com/example/repo/blob/{SHA}/f{i}.py" for i in range(6)]
        with self.assertRaisesRegex(UserError, "1-5"):
            self.contract.audit(pid, json.dumps(many), SHA)

    def test_github_http_error_is_inconclusive_and_skips_llm(self):
        pid = self.create_policy()
        self.runtime.statuses["contracts/example.py"] = 404
        self.set_sender(AUDITOR)
        audit_id = self.contract.audit(pid, self.manifest(), SHA)
        audit = self.contract.get_audit(audit_id)
        self.assertEqual(audit["outcome"], "INCONCLUSIVE")
        self.assertIn("HTTP status 404", audit["summary"])
        self.assertEqual(self.runtime.prompts, [])

    def test_github_response_ref_mismatch_is_inconclusive(self):
        pid = self.create_policy()
        self.runtime.response_ref = OTHER_SHA
        self.set_sender(AUDITOR)
        audit_id = self.contract.audit(pid, self.manifest(), SHA)
        audit = self.contract.get_audit(audit_id)
        self.assertEqual(audit["outcome"], "INCONCLUSIVE")
        self.assertIn("ref does not match", audit["summary"])

    def test_github_response_path_mismatch_is_inconclusive(self):
        pid = self.create_policy()
        self.runtime.response_path_override = "other.py"
        self.set_sender(AUDITOR)
        audit_id = self.contract.audit(pid, self.manifest(), SHA)
        audit = self.contract.get_audit(audit_id)
        self.assertEqual(audit["outcome"], "INCONCLUSIVE")
        self.assertIn("path does not match", audit["summary"])

    def test_forged_line_or_quote_cannot_verify(self):
        pid = self.create_policy()
        forged = report()
        forged["reports"][0]["citations"][0]["quote"] = "unguarded write"
        self.runtime.prompt_results = [forged, validator_accept(("UNKNOWN",))]
        self.set_sender(AUDITOR)
        audit_id = self.contract.audit(pid, self.manifest(), SHA)
        audit = self.contract.get_audit(audit_id)
        self.assertEqual(audit["outcome"], "INCONCLUSIVE")
        self.assertIn("citations do not match", audit["summary"])

    def test_pass_without_citation_becomes_inconclusive(self):
        leader = report(citations=False)
        audit = self.run_audit(leader, validator_accept(("UNKNOWN",)))
        self.assertEqual(audit["outcome"], "INCONCLUSIVE")

    def test_pass_below_coverage_threshold_becomes_inconclusive(self):
        leader = report(coverage=649)
        audit = self.run_audit(leader, validator_accept(("UNKNOWN",)))
        self.assertEqual(audit["outcome"], "INCONCLUSIVE")
        self.assertIn("coverage threshold", audit["summary"])

    def test_json_string_and_extra_fields_are_projected_safely(self):
        leader = report()
        leader["provider_note"] = "ignored representation metadata"
        leader["reports"][0]["provider_note"] = "ignored"
        leader["reports"][0]["citations"][0]["provider_note"] = "ignored"
        normal = self.module._normalise_report(json.dumps(leader), 1)

        self.assertEqual(normal["reports"][0]["status"], "PASS")
        self.assertEqual(normal["reports"][0]["citations"][0]["quote"], "assert sender == owner")
        self.assertNotIn("provider_note", normal)
        self.assertNotIn("provider_note", normal["reports"][0])

    def test_malformed_leader_output_becomes_inconclusive(self):
        audit = self.run_audit({"unexpected": True}, validator_accept(("UNKNOWN",)))
        self.assertEqual(audit["outcome"], "INCONCLUSIVE")
        self.assertIn("malformed", audit["summary"])

    def test_validator_semantic_rejection_aborts_state_write(self):
        pid = self.create_policy()
        self.runtime.prompt_results = [report(), {"valid": False, "status_vector": ["PASS"], "reason": "unsupported"}]
        self.set_sender(AUDITOR)
        with self.assertRaises(ConsensusDisagreement):
            self.contract.audit(pid, self.manifest(), SHA)
        self.assertEqual(self.contract.get_audit_count(), 0)

    def test_validator_status_mismatch_aborts_state_write(self):
        pid = self.create_policy()
        self.runtime.prompt_results = [report(), validator_accept(("FAIL",))]
        self.set_sender(AUDITOR)
        with self.assertRaises(ConsensusDisagreement):
            self.contract.audit(pid, self.manifest(), SHA)
        self.assertEqual(self.contract.get_audit_count(), 0)

    def test_malformed_validator_output_aborts_state_write(self):
        pid = self.create_policy()
        self.runtime.prompt_results = [report(), {"valid": True}]
        self.set_sender(AUDITOR)
        with self.assertRaises(ConsensusDisagreement):
            self.contract.audit(pid, self.manifest(), SHA)

    def test_duplicate_audit_is_rejected_but_different_policy_is_allowed(self):
        first = self.run_audit()
        self.runtime.prompt_results = [report(), validator_accept()]
        with self.assertRaisesRegex(UserError, "already audited"):
            self.contract.audit(first["policy_id"], self.manifest(), SHA)
        second_policy = self.create_policy()
        self.runtime.prompt_results = [report(), validator_accept()]
        self.contract.audit(second_policy, self.manifest(), SHA)
        self.assertEqual(self.contract.get_audit_count(), 2)

    def test_find_audit_uses_content_addressed_manifest_hash(self):
        audit = self.run_audit()
        found = self.contract.find_audit(audit["policy_id"], audit["manifest_hash"])
        self.assertEqual(found, audit["id"])
        self.assertEqual(self.contract.find_audit(audit["policy_id"], "0" * 64), 0)

    def test_missing_policy_audit_and_invalid_manifest_hash_revert(self):
        with self.assertRaisesRegex(UserError, "policy not found"):
            self.contract.get_policy(1)
        with self.assertRaisesRegex(UserError, "audit not found"):
            self.contract.get_audit(1)
        with self.assertRaisesRegex(UserError, "manifest_hash invalid"):
            self.contract.find_audit(1, "bad")

    def test_multiple_files_are_fetched_with_the_same_sha(self):
        audit = self.run_audit(paths=("contracts/example.py", "README.md"))
        self.assertEqual(len(audit["files"]), 2)
        self.assertEqual(len(self.runtime.web_requests), 4)  # leader + validator
        self.assertTrue(all(f"?ref={SHA}" in url for url, _ in self.runtime.web_requests))

    def test_total_byte_cap_fails_closed(self):
        pid = self.create_policy()
        self.runtime.files["contracts/example.py"] = "x" * 12000
        self.runtime.files["README.md"] = "y" * 12000
        self.runtime.files["a.py"] = "a" * 12000
        self.runtime.files["b.py"] = "b" * 12000
        self.set_sender(AUDITOR)
        audit_id = self.contract.audit(
            pid, self.manifest(("contracts/example.py", "README.md", "a.py", "b.py")), SHA
        )
        self.assertEqual(self.contract.get_audit(audit_id)["outcome"], "INCONCLUSIVE")

    def test_prompt_labels_sources_as_untrusted_and_requires_counterexample(self):
        self.run_audit()
        leader_prompt, validator_prompt = self.runtime.prompts
        self.assertIn("UNTRUSTED_SOURCES", leader_prompt)
        self.assertIn("counterexample", leader_prompt)
        self.assertIn("untrusted data", validator_prompt)


if __name__ == "__main__":
    unittest.main()
