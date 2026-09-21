"""
API Integration Tests for Bitcoin Forensics Backend Server
"""

import os
import sys
import unittest
from fastapi.testclient import TestClient

# Ensure root workspace is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.server import app

class TestBitcoinForensicsAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_root_and_profile(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "ONLINE")

        profile_res = self.client.get("/api/system/profile")
        self.assertEqual(profile_res.status_code, 200)
        pdata = profile_res.json()
        self.assertIn("os_name", pdata)
        self.assertIn("total_ram_gb", pdata)

    def test_sample_case_scan(self):
        res = self.client.post("/api/scan/sample")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["mode"], "SAMPLE_BENCHMARK_CASE")
        self.assertIn("volatile_memory", data)
        self.assertGreater(len(data["volatile_memory"]["seeds"]), 0)
        self.assertGreater(len(data["volatile_memory"]["private_keys"]), 0)

    def test_evidence_ledger(self):
        # Trigger scan to populate evidence items
        self.client.post("/api/scan/sample")
        res = self.client.get("/api/evidence/ledger")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertGreater(data["total_items"], 0)

    def test_report_generation(self):
        res = self.client.get("/api/report/generate")
        self.assertEqual(res.status_code, 200)
        report = res.json()
        self.assertIn("report_id", report)
        self.assertIn("standard_compliance", report)

if __name__ == "__main__":
    unittest.main()
