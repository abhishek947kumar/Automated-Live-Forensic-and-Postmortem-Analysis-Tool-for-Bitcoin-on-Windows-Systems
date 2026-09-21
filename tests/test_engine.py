"""
Unit tests for the Bitcoin Digital Forensics Engine
Validates memory pattern scanners, Berkeley DB detectors, ROT13 UserAssist, and Chain of Custody.
"""

import os
import sys
import unittest

# Ensure forensic_engine is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from forensic_engine.bip39_wordlist import is_valid_bip39_phrase, BIP39_SET
from forensic_engine.live_memory import scan_buffer_for_crypto_artifacts, format_hex_dump
from forensic_engine.registry_analyzer import rot13, parse_userassist_entry
from forensic_engine.filesystem_scanner import check_file_format, BERKELEY_DB_MAGIC_BE
from forensic_engine.chain_of_custody import ChainOfCustodyManager
from forensic_engine.sample_corpus import create_sample_case_directory

class TestBitcoinForensicsEngine(unittest.TestCase):

    def test_bip39_wordlist_and_validation(self):
        self.assertEqual(len(BIP39_SET), 2048)
        valid_12 = ["abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse", "access", "accident"]
        self.assertTrue(is_valid_bip39_phrase(valid_12))
        invalid_words = ["notaword", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse", "access", "accident"]
        self.assertFalse(is_valid_bip39_phrase(invalid_words))

    def test_rot13_decryption(self):
        # ROT13 decryption test
        encoded = "ryrpgehz.rkr"
        self.assertEqual(rot13(encoded), "electrum.exe")
        encoded_btc = "ovgpbva-dg.rkr"
        self.assertEqual(rot13(encoded_btc), "bitcoin-qt.exe")

    def test_chain_of_custody_hashing(self):
        sample_data = b"Bitcoin Forensic Digital Evidence 2026"
        sha256, md5, size = ChainOfCustodyManager.calculate_hashes(sample_data)
        self.assertEqual(len(sha256), 64)
        self.assertEqual(len(md5), 32)
        self.assertEqual(size, len(sample_data))

    def test_memory_artifact_extraction(self):
        raw = b"""
        Some background memory noise...
        Seed: shadow galaxy frozen secret matrix orbit winter weapon dynamic echo puzzle abandon
        Key: KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn
        Addr: bc1q0satoshi921forensicshadowproof7x49k
        Legacy: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
        Conf: rpcuser=btc_user\nrpcpassword=SuperSecureSecretPassword99\n
        """
        results = scan_buffer_for_crypto_artifacts(raw, "TestMemory")
        self.assertGreater(len(results["seeds"]), 0)
        self.assertGreater(len(results["private_keys"]), 0)
        self.assertGreater(len(results["public_addresses"]), 0)
        self.assertGreater(len(results["credentials"]), 0)

    def test_sample_case_generation_and_detection(self):
        test_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "test_case_output"))
        case_files = create_sample_case_directory(test_dir)
        self.assertTrue(os.path.exists(case_files["memory_dump"]))
        self.assertTrue(os.path.exists(case_files["bitcoin_remnant"]))
        
        # Verify Berkeley DB format check
        fmt = check_file_format(case_files["bitcoin_remnant"])
        self.assertEqual(fmt["format"], "BERKELEY_DB")
        
        # Clean up
        import shutil
        shutil.rmtree(test_dir, ignore_errors=True)

if __name__ == "__main__":
    unittest.main()
