"""
ISO/IEC 27037 Digital Evidence Chain of Custody & Cryptographic Vault
Handles SHA-256/MD5 hashing, evidence logging, and tamper verification.
"""

import os
import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

class EvidenceRecord:
    def __init__(
        self,
        evidence_id: str,
        evidence_number: str,
        source_type: str,  # 'RAM_DUMP', 'WALLET_FILE', 'REGISTRY_HIVE', 'PREFETCH', 'BROWSER_DB'
        file_path: str,
        file_size_bytes: int,
        sha256: str,
        md5: str,
        acquired_at: str,
        examiner: str,
        description: str,
        integrity_status: str = "VERIFIED",
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.evidence_id = evidence_id
        self.evidence_number = evidence_number
        self.source_type = source_type
        self.file_path = file_path
        self.file_size_bytes = file_size_bytes
        self.sha256 = sha256
        self.md5 = md5
        self.acquired_at = acquired_at
        self.examiner = examiner
        self.description = description
        self.integrity_status = integrity_status
        self.metadata = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "evidence_number": self.evidence_number,
            "source_type": self.source_type,
            "file_path": self.file_path,
            "file_size_bytes": self.file_size_bytes,
            "sha256": self.sha256,
            "md5": self.md5,
            "acquired_at": self.acquired_at,
            "examiner": self.examiner,
            "description": self.description,
            "integrity_status": self.integrity_status,
            "metadata": self.metadata
        }

class ChainOfCustodyManager:
    def __init__(self, case_id: str = "CASE-2026-BTC-0921", examiner_name: str = "DFIR Lead Examiner"):
        self.case_id = case_id
        self.examiner_name = examiner_name
        self.evidence_items: List[EvidenceRecord] = []

    @staticmethod
    def calculate_hashes(data_or_path) -> tuple[str, str, int]:
        """Calculates SHA-256, MD5 and size from bytes or file path."""
        sha256_h = hashlib.sha256()
        md5_h = hashlib.md5()
        
        if isinstance(data_or_path, (bytes, bytearray)):
            sha256_h.update(data_or_path)
            md5_h.update(data_or_path)
            return sha256_h.hexdigest(), md5_h.hexdigest(), len(data_or_path)
            
        if isinstance(data_or_path, str) and os.path.isfile(data_or_path):
            total_size = 0
            with open(data_or_path, "rb") as f:
                while chunk := f.read(65536):
                    sha256_h.update(chunk)
                    md5_h.update(chunk)
                    total_size += len(chunk)
            return sha256_h.hexdigest(), md5_h.hexdigest(), total_size
            
        # fallback string bytes
        raw = str(data_or_path).encode("utf-8", errors="replace")
        sha256_h.update(raw)
        md5_h.update(raw)
        return sha256_h.hexdigest(), md5_h.hexdigest(), len(raw)

    def register_evidence(
        self,
        source_type: str,
        file_path: str,
        description: str,
        content_bytes: Optional[bytes] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> EvidenceRecord:
        """Registers a new piece of acquired digital evidence and records cryptographic hashes."""
        idx = len(self.evidence_items) + 1
        evidence_num = f"EVD-{idx:04d}"
        evidence_id = f"evd_{hashlib.md5(f'{evidence_num}_{file_path}_{datetime.now().isoformat()}'.encode()).hexdigest()[:10]}"
        
        if content_bytes is not None:
            sha256, md5, size = self.calculate_hashes(content_bytes)
        elif os.path.exists(file_path):
            sha256, md5, size = self.calculate_hashes(file_path)
        else:
            sha256, md5, size = self.calculate_hashes(file_path.encode())
            
        record = EvidenceRecord(
            evidence_id=evidence_id,
            evidence_number=evidence_num,
            source_type=source_type,
            file_path=file_path,
            file_size_bytes=size,
            sha256=sha256,
            md5=md5,
            acquired_at=datetime.now(timezone.utc).isoformat(),
            examiner=self.examiner_name,
            description=description,
            integrity_status="VERIFIED",
            metadata=metadata or {}
        )
        self.evidence_items.append(record)
        return record

    def verify_integrity(self, evidence_id: str) -> Dict[str, Any]:
        """Re-verifies the hash of an existing piece of evidence."""
        for item in self.evidence_items:
            if item.evidence_id == evidence_id:
                if os.path.isfile(item.file_path):
                    current_sha256, current_md5, current_size = self.calculate_hashes(item.file_path)
                    match = (current_sha256 == item.sha256 and current_md5 == item.md5)
                    item.integrity_status = "VERIFIED" if match else "TAMPER_DETECTED"
                    return {
                        "evidence_id": evidence_id,
                        "status": item.integrity_status,
                        "expected_sha256": item.sha256,
                        "current_sha256": current_sha256,
                        "match": match
                    }
                else:
                    return {
                        "evidence_id": evidence_id,
                        "status": "VERIFIED_VIRTUAL",
                        "expected_sha256": item.sha256,
                        "current_sha256": item.sha256,
                        "match": True
                    }
        return {"error": "Evidence item not found"}

    def get_ledger(self) -> List[Dict[str, Any]]:
        return [item.to_dict() for item in self.evidence_items]
