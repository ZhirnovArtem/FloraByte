import os
import shutil
from pathlib import Path
import zipfile

from security_scanners.core.models import SourceFile, ScanInput
from security_scanners.secrets.scanner import SecretsScanner
from security_scanners.sca.scanner import ScaScanner

def main():
    test_dir = Path("test_repo")
    test_dir.mkdir(exist_ok=True)

    # 1. Создаем файлы
    (test_dir / "Config.kt").write_text('val password = "supersecret123"', encoding="utf-8")
    (test_dir / "build.gradle.kts").write_text('''
    dependencies {
        implementation("org.apache.logging.log4j:log4j-core:2.14.0")
    }
    ''', encoding="utf-8")

    # 2. Имитируем загрузку ZIP
    zip_path = "test_repo.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.write(test_dir / "Config.kt", "Config.kt")
        zf.write(test_dir / "build.gradle.kts", "build.gradle.kts")

    source_files = []
    with zipfile.ZipFile(zip_path, "r") as zf:
        for file_info in zf.infolist():
            if not file_info.is_dir():
                content = zf.read(file_info.filename).decode("utf-8", errors="ignore")
                source_files.append(SourceFile(path=file_info.filename, content=content))

    scan_input = ScanInput(repo_path="test_repo.zip", files=source_files)

    # 3. Запускаем Secrets Scanner
    print("\n--- 🔑 Secrets Scanner ---")
    secrets_scanner = SecretsScanner()
    secrets_result = secrets_scanner.scan(scan_input)
    if not secrets_result.findings:
        print("Секретов не найдено.")
    for finding in secrets_result.findings:
        print(f"[{finding.severity.name}] {finding.type} в {finding.file}:{finding.line}")
        print(f"   Evidence: {finding.evidence}")

    # 4. Запускаем SCA Scanner
    print("\n--- 📦 SCA Scanner ---")
    sca_scanner = ScaScanner()
    sca_result = sca_scanner.scan(scan_input)
    if not sca_result.findings:
        print("Уязвимых зависимостей не найдено.")
    for finding in sca_result.findings:
        print(f"[{finding.severity.name}] {finding.description}")
        print(f"   File: {finding.file}:{finding.line}")
        print(f"   Package: {finding.metadata.get('package')}:{finding.metadata.get('version')}")

    # 5. Очистка временных файлов
    shutil.rmtree(test_dir)
    os.remove(zip_path)
    print("\nГотово!")

if __name__ == "__main__":
    main()