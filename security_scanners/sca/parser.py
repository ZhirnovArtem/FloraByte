"""Small in-house Gradle dependency parser (no third-party scanner/rules engine).

Covers common Gradle Kotlin DSL declarations, multiline add(...) calls,
providers.gradleProperty(...) + gradle.properties resolution, simple version variables,
version-catalog aliases and locked versions; deliberately not a full Kotlin parser.
"""
from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from typing import Mapping


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


_CONFIG = (
    r"implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|"
    r"kapt|annotationProcessor|debugImplementation|runtimeClasspath"
)


def _strip_comments_preserve_lines(content: str) -> str:
    """Replace // and /* ... */ comments with spaces while keeping newlines intact for line numbers."""
    # Block comments first
    def _blank_block(match: re.Match[str]) -> str:
        return "\n" * match.group(0).count("\n")

    cleaned = re.sub(r"/\*[\s\S]*?\*/", _blank_block, content)
    # Single-line // comments (avoid stripping :// in URLs by requiring start of line or whitespace before //)
    cleaned = re.sub(r"(?m)(^|\s)//[^\n]*", lambda m: m.group(1), cleaned)
    return cleaned


class GradleDependencyParser:
    _QUOTED = re.compile(
        rf'''(?ms)\b({_CONFIG})\s*\(\s*["']([^"':\s]+):([^"':\s]+):([^"']+)["']\s*,?\s*\)'''
    )
    _ADD_QUOTED = re.compile(
        rf'''(?ms)\badd\s*\(\s*["']({_CONFIG})["']\s*,\s*["']([^"':\s]+):([^"':\s]+):([^"']+)["']\s*,?\s*\)'''
    )
    _NAMED = re.compile(
        rf'''(?ms)\b({_CONFIG})\s*\(\s*group\s*=\s*["']([^"']+)["']\s*,\s*name\s*=\s*["']([^"']+)["']\s*,\s*version\s*=\s*["']([^"']+)["']\s*,?\s*\)'''
    )
    _CATALOG = re.compile(rf'(?m)^\s*({_CONFIG})\s*\(\s*libs\.([\w.\-]+)\s*\)')
    _VAR = re.compile(r'''(?m)\b(?:val|var|def)\s+([a-zA-Z_]\w*)\s*(?::\s*String\s*)?=\s*["']([^"']+)["']''')
    _GRADLE_PROP_VAR = re.compile(
        r'''(?m)\b(?:val|var|def)\s+([a-zA-Z_]\w*)\s*(?::\s*String\s*)?=\s*providers\.gradleProperty\(\s*["']([^"']+)["']\s*\)(?:\s*\.\s*(?:get\(\)|orNull|getOrElse\([^)]*\)))?'''
    )
    _INLINE_GRADLE_PROP = re.compile(
        r'''\$\{?\s*providers\.gradleProperty\(\s*["']([^"']+)["']\s*\)(?:\s*\.\s*(?:get\(\)|orNull|getOrElse\([^)]*\)))?\s*\}?'''
    )
    _EXTRA = re.compile(r'''(?m)\b(?:extra\[["']([\w.\-]+)["']\]|ext\.([\w.\-]+))\s*=\s*["']([^"']+)["']''')
    _INTERPOLATION = re.compile(r'\$\{?([A-Za-z_]\w*)\}?')
    _LOCK = re.compile(r'^\s*([^\s:#=]+):([^\s:#=]+):([^\s:#=]+)\s*=')

    @staticmethod
    def variables(contents: list[str]) -> dict[str, str]:
        variables: dict[str, str] = {}
        prop_bindings: list[tuple[str, str]] = []

        for content in contents:
            for match in GradleDependencyParser._VAR.finditer(content):
                variables[match.group(1)] = match.group(2)
            for match in GradleDependencyParser._EXTRA.finditer(content):
                variables[match.group(1) or match.group(2)] = match.group(3)
            for match in GradleDependencyParser._GRADLE_PROP_VAR.finditer(content):
                prop_bindings.append((match.group(1), match.group(2)))
            for line in content.splitlines():
                m = re.fullmatch(r'\s*([A-Za-z_]\w*)\s*=\s*([\w.\-+]+)\s*', line)
                if m:
                    variables.setdefault(m.group(1), m.group(2))

        for var_name, prop_key in prop_bindings:
            if prop_key in variables:
                variables[var_name] = variables[prop_key]

        return variables

    @staticmethod
    def catalog(content: str) -> dict[str, tuple[str, str, str]]:
        """Read aliases from gradle/libs.versions.toml, including version.ref."""
        try:
            doc = tomllib.loads(content)
        except (ValueError, TypeError):
            return {}
        versions = doc.get("versions", {})
        aliases: dict[str, tuple[str, str, str]] = {}
        for alias, item in doc.get("libraries", {}).items():
            if isinstance(item, str):
                pieces = item.split(":")
                if len(pieces) != 3:
                    continue
                group, artifact, version = pieces
            elif isinstance(item, dict):
                module = item.get("module") or ""
                if module and ":" in module:
                    group, artifact = module.split(":", 1)
                else:
                    group, artifact = item.get("group", ""), item.get("name", "")
                ver = item.get("version", "")
                if isinstance(ver, dict):
                    version = versions.get(ver.get("ref", ""), ver.get("required", ""))
                else:
                    version = ver
                if isinstance(version, dict):
                    version = version.get("require", "") or version.get("strictly", "")
            else:
                continue
            if group and artifact and version:
                aliases[alias.replace("-", ".").replace("_", ".")] = (str(group), str(artifact), str(version))
        return aliases

    @classmethod
    def locked_dependencies(cls, content: str) -> list[GradleDependency]:
        out = []
        for line_no, line in enumerate(content.splitlines(), 1):
            m = cls._LOCK.match(line)
            if m and not cls._is_dynamic(m.group(3)):
                out.append(GradleDependency("lockfile", m.group(1), m.group(2), m.group(3), line_no))
        return out

    def parse(
        self,
        content: str,
        file_path: str,
        variables: Mapping[str, str] | None = None,
        aliases: Mapping[str, tuple[str, str, str]] | None = None,
    ) -> list[GradleDependency]:
        deps: list[GradleDependency] = []
        cleaned = _strip_comments_preserve_lines(content)
        vars_all = {**self.variables([cleaned]), **(variables or {})}

        for pattern in (self._QUOTED, self._ADD_QUOTED, self._NAMED):
            for match in pattern.finditer(cleaned):
                configuration, group, artifact, version = match.groups()
                version = self._resolve(version, vars_all)
                if self._is_dynamic(version):
                    continue
                deps.append(
                    GradleDependency(
                        configuration,
                        group.strip(),
                        artifact.strip(),
                        version,
                        self._line_of(cleaned, match.start()),
                    )
                )

        for match in self._CATALOG.finditer(cleaned):
            alias = match.group(2).replace("-", ".").replace("_", ".")
            item = (aliases or {}).get(alias)
            if item:
                group, artifact, version = item
                version = self._resolve(version, vars_all)
                if not self._is_dynamic(version):
                    deps.append(
                        GradleDependency(
                            match.group(1),
                            group,
                            artifact,
                            version,
                            self._line_of(cleaned, match.start()),
                        )
                    )

        unique: list[GradleDependency] = []
        seen = set()
        for dep in deps:
            key = (dep.package_name, dep.version)
            if key not in seen:
                unique.append(dep)
                seen.add(key)
        return unique

    @classmethod
    def _resolve(cls, version: str, variables: Mapping[str, str]) -> str:
        result = version.strip()
        result = cls._INLINE_GRADLE_PROP.sub(
            lambda m: variables.get(m.group(1), m.group(0)),
            result,
        )
        for _ in range(4):  # bounded recursive interpolation
            new = cls._INTERPOLATION.sub(lambda m: variables.get(m.group(1), m.group(0)), result)
            if new == result:
                break
            result = new
        return result

    @staticmethod
    def _is_dynamic(version: str) -> bool:
        return "+" in version or "latest." in version or "$" in version or not version.strip()

    @staticmethod
    def _line_of(content: str, offset: int) -> int:
        return content.count("\n", 0, offset) + 1
