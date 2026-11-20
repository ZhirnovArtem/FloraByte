from enum import Enum

class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[self.value]

    @classmethod
    def max_of(cls, *values: "Severity | str | None") -> "Severity | None":
        best = None
        for v in values:
            if v is None:
                continue
            s = cls(v) if not isinstance(v, cls) else v
            if best is None or s.rank > best.rank:
                best = s
        return best
