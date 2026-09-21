"""統一 CVSS 模型：v3.1 與 v4.0 並存，score 與 vector 一律成對保留。

兩個版本共用 0–10 分數與同一組嚴重度分級（FIRST 對 v3.1、v4.0 的 Qualitative
Severity Rating 定義相同），但計分公式不同，同一個漏洞在兩版下常得到不同分數。
因此這裡不做任何跨版本換算：每個分數都帶著自己的版本、vector 與評分者，
選用哪一版由呼叫端依外部化的偏好順序決定，並在輸出裡標明。
"""

from __future__ import annotations

from dataclasses import dataclass

SUPPORTED_VERSIONS = ("3.1", "4.0")
SEVERITY_UNKNOWN = "UNKNOWN"

# (下限, 分級)；上限由下一級的下限決定，10.0 為封頂
_SEVERITY_BANDS = ((9.0, "CRITICAL"), (7.0, "HIGH"), (4.0, "MEDIUM"), (0.1, "LOW"), (0.0, "NONE"))


class CvssError(ValueError):
    """CVSS 資料自相矛盾或不在支援範圍。"""


def version_from_vector(vector: str) -> str:
    """從 vector 前綴讀版本，例如 'CVSS:3.1/AV:N/...' → '3.1'。"""
    if not vector or not vector.startswith("CVSS:"):
        raise CvssError(f"vector must start with 'CVSS:' — got {vector!r}")
    version = vector.split("/", 1)[0][len("CVSS:"):]
    if version not in SUPPORTED_VERSIONS:
        raise CvssError(f"unsupported CVSS version {version!r} in vector {vector!r}")
    return version


def severity_for(score: float) -> str:
    """0–10 分數對應的定性分級，v3.1 與 v4.0 共用。"""
    if not 0.0 <= score <= 10.0:
        raise CvssError(f"base score must be within 0–10, got {score}")
    for floor, label in _SEVERITY_BANDS:
        if score >= floor:
            return label
    return "NONE"


@dataclass(frozen=True)
class CvssScore:
    version: str
    base_score: float
    vector: str
    severity: str
    scorer: str  # 例如 nvd@nist.gov 或 CNA 的信箱
    scorer_type: str  # NVD 的 "Primary" / "Secondary"

    @property
    def is_primary(self) -> bool:
        return self.scorer_type == "Primary"


def make_score(*, version: str, base_score: float, vector: str,
               scorer: str = "", scorer_type: str = "") -> CvssScore:
    """建立一筆分數並檢查自洽：宣告版本必須等於 vector 前綴。"""
    vector_version = version_from_vector(vector)
    if version != vector_version:
        raise CvssError(
            f"declared version {version} does not match vector prefix {vector_version}"
        )
    score = float(base_score)
    return CvssScore(
        version=version,
        base_score=score,
        vector=vector,
        severity=severity_for(score),
        scorer=scorer,
        scorer_type=scorer_type,
    )


@dataclass(frozen=True)
class CvssSet:
    """同一個 CVE 的所有可用分數。空集合代表『有這個 CVE，但沒人評分』。"""

    scores: tuple[CvssScore, ...] = ()

    def versions(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(s.version for s in self.scores))

    def for_version(self, version: str) -> CvssScore | None:
        """同版本有多個評分者時，NVD 的 Primary 優先；其餘照原始順序。"""
        candidates = [s for s in self.scores if s.version == version]
        if not candidates:
            return None
        return next((s for s in candidates if s.is_primary), candidates[0])

    def preferred(self, order: tuple[str, ...] | list[str]) -> CvssScore | None:
        """依偏好順序取第一個存在的版本；全部缺席回 None，交由呼叫端標 UNKNOWN。"""
        for version in order:
            score = self.for_version(version)
            if score is not None:
                return score
        return None

    def to_dicts(self) -> list[dict]:
        return [vars(s) for s in self.scores]

    @classmethod
    def from_dicts(cls, items: list[dict]) -> CvssSet:
        return cls(tuple(CvssScore(**item) for item in items))
