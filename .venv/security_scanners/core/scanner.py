from abc import ABC, abstractmethod
from .models import ScanInput, ScanResult

class SecurityScanner(ABC):
    @property
    @abstractmethod
    def id(self) -> str: ...

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def scan(self, scan_input: ScanInput) -> ScanResult: ...