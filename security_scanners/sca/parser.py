from __future__ import annotations
import re
from dataclasses import dataclass

@dataclass
class GradleDependency:
    configuration: str
    group: str
    artifact: str
    version: str
    line: int

    @property
    def package_name(self) -> str:
        return f"{self.group}:{self.artifact}"

class GradleDependencyParser:
    _QUOTED = re.compile(r"""(?m)^\s*(implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|kapt|annotationProcessor)\s*\(\s*["']([^"':]+):([^"':]+):([^"')]+)["']\s*\)""")
    _NAMED = re.compile(r"""(?m)^\s*(implementation|api|compileOnly|runtimeOnly|testImplementation)\s*\(\s*group\s*=\s*["']([^"']+)["']\s*,\s*name\s*=\s*["']([^"']+)["']\s*,\s*version\s*=\s*["']([^"']+)["']\s*\)""")

    def parse(self, content: str, file_path: str) -> list[GradleDependency]:
        deps: list[GradleDependency] = []
        for m in self._QUOTED.finditer(content):
            config, group, artifact, version = m.groups()
            if self._is_dynamic(version): continue
            deps.append(GradleDependency(config.strip(), group.strip(), artifact.strip(), version.strip(), self._line_of(content, m.start())))
        for m in self._NAMED.finditer(content):
            config, group, artifact, version = m.groups()
            if self._is_dynamic(version): continue
            deps.append(GradleDependency(config.strip(), group.strip(), artifact.strip(), version.strip(), self._line_of(content, m.start())))
        seen: set[str] = set()
        unique: list[GradleDependency] = []
        for d in deps:
            key = f"{d.package_name}:{d.version}"
            if key in seen: continue
            seen.add(key)
            unique.append(d)
        return unique

    @staticmethod
    def _is_dynamic(version: str) -> bool:
        return "+" in version or "latest." in version or version.startswith("$") or not version.strip()

    @staticmethod
    def _line_of(content: str, offset: int) -> int:
        return content.count("\n", 0, offset) + 1