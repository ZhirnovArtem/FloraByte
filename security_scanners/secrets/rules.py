from __future__ import annotations
import re
from dataclasses import dataclass, field
from ..core.models import Severity

@dataclass
class SecretRule:
    id: str
    name: str
    pattern: re.Pattern[str]
    severity: Severity
    description: str
    recommendation: str
    allowlist: list[re.Pattern[str]] = field(default_factory=list)

class DefaultSecretRules:
    @staticmethod
    def all() -> list[SecretRule]:
        return [
            DefaultSecretRules.hardcoded_password(), DefaultSecretRules.hardcoded_api_key(),
            DefaultSecretRules.bearer_token(), DefaultSecretRules.private_key(),
            DefaultSecretRules.aws_access_key(), DefaultSecretRules.aws_secret_key(),
            DefaultSecretRules.google_api_key(), DefaultSecretRules.telegram_bot_token(),
            DefaultSecretRules.slack_token(), DefaultSecretRules.jwt_token(),
            DefaultSecretRules.jdbc_url_with_password(), DefaultSecretRules.mongodb_uri_with_password(),
            DefaultSecretRules.postgres_uri_with_password(), DefaultSecretRules.github_token(),
            DefaultSecretRules.generic_secret_assignment(),
        ]

    @staticmethod
    def hardcoded_password() -> SecretRule:
        return SecretRule(
            id="hardcoded-password", name="Hardcoded password",
            pattern=re.compile(r"""(?i)(password|passwd|pwd)\s*[:=]\s*["']([^"']{4,})["']"""),
            severity=Severity.HIGH, description="Пароль жёстко задан в коде",
            recommendation="Вынесите пароль в переменные окружения или Vault",
            allowlist=[re.compile(r"""(?i)(password|passwd|pwd)\s*[:=]\s*["'](\$\{[^}]+\}|changeit|test|example|dummy|changeme|your[-_]?password)["']""")]
        )

    @staticmethod
    def hardcoded_api_key() -> SecretRule:
        return SecretRule(
            id="hardcoded-api-key", name="Hardcoded API key",
            pattern=re.compile(r"""(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*["']([A-Za-z0-9_\-]{12,})["']"""),
            severity=Severity.HIGH, description="API-ключ жёстко задан в коде",
            recommendation="Вынесите ключ в переменные окружения или Vault",
            allowlist=[re.compile(r"""(?i)(api[_-]?key|apikey)\s*[:=]\s*["'](\$\{[^}]+\}|your[-_]?api[-_]?key|example|dummy)["']""")]
        )

    @staticmethod
    def bearer_token() -> SecretRule:
        return SecretRule(
            id="bearer-token", name="Bearer token",
            pattern=re.compile(r"""(?i)bearer\s+([A-Za-z0-9\-._~+/]{20,}=*)"""),
            severity=Severity.HIGH, description="Bearer-токен в коде",
            recommendation="Вынесите токен в переменные окружения",
            allowlist=[re.compile(r"""(?i)bearer\s+(\$\{[^}]+\}|<token>|xxx+)""")]
        )

    @staticmethod
    def private_key() -> SecretRule:
        return SecretRule(
            id="private-key", name="Private key",
            pattern=re.compile(r"""-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"""),
            severity=Severity.CRITICAL, description="Приватный ключ в репозитории",
            recommendation="Удалите ключ из репозитория и ротируйте его"
        )

    @staticmethod
    def aws_access_key() -> SecretRule:
        return SecretRule(
            id="aws-access-key", name="AWS Access Key",
            pattern=re.compile(r"""AKIA[0-9A-Z]{16}"""),
            severity=Severity.CRITICAL, description="Найден AWS Access Key",
            recommendation="Отзовите ключ через IAM и используйте IAM Role",
            allowlist=[re.compile(r"""AKIAIOSFODNN7EXAMPLE""")]
        )

    @staticmethod
    def aws_secret_key() -> SecretRule:
        return SecretRule(
            id="aws-secret-key", name="AWS Secret Key",
            pattern=re.compile(r"""(?i)(aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?"""),
            severity=Severity.CRITICAL, description="AWS Secret Access Key в коде",
            recommendation="Отзовите ключ через IAM и используйте IAM Role"
        )

    @staticmethod
    def google_api_key() -> SecretRule:
        return SecretRule(
            id="google-api-key", name="Google API Key",
            pattern=re.compile(r"""AIza[0-9A-Za-z\-_]{35}"""),
            severity=Severity.CRITICAL, description="Google API Key в коде",
            recommendation="Отзовите ключ в Google Cloud Console"
        )

    @staticmethod
    def telegram_bot_token() -> SecretRule:
        return SecretRule(
            id="telegram-bot-token", name="Telegram bot token",
            pattern=re.compile(r"""\d{8,10}:[A-Za-z0-9_-]{35}"""),
            severity=Severity.CRITICAL, description="Токен Telegram-бота",
            recommendation="Отзовите токен через BotFather"
        )

    @staticmethod
    def slack_token() -> SecretRule:
        return SecretRule(
            id="slack-token", name="Slack token",
            pattern=re.compile(r"""xox[baprs]-[0-9A-Za-z\-]{10,}"""),
            severity=Severity.CRITICAL, description="Slack-токен в коде",
            recommendation="Отзовите токен в Slack Admin"
        )

    @staticmethod
    def jwt_token() -> SecretRule:
        return SecretRule(
            id="jwt-token", name="JWT token",
            pattern=re.compile(r"""eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"""),
            severity=Severity.HIGH, description="JWT-токен в коде",
            recommendation="Не храните JWT в коде; используйте переменные окружения"
        )

    @staticmethod
    def jdbc_url_with_password() -> SecretRule:
        return SecretRule(
            id="jdbc-url-with-password", name="JDBC URL with password",
            pattern=re.compile(r"""jdbc:[a-z]+://[^"'\s]+password=[^"'\s&]+""", re.IGNORECASE),
            severity=Severity.HIGH, description="Пароль в строке подключения JDBC",
            recommendation="Вынесите пароль в конфигурацию окружения"
        )

    @staticmethod
    def mongodb_uri_with_password() -> SecretRule:
        return SecretRule(
            id="mongodb-uri-with-password", name="MongoDB URI with password",
            pattern=re.compile(r"""mongodb(\+srv)?://[^:]+:[^@]+@[^"'\s]+"""),
            severity=Severity.HIGH, description="Пароль в MongoDB URI",
            recommendation="Вынесите пароль в конфигурацию окружения"
        )

    @staticmethod
    def postgres_uri_with_password() -> SecretRule:
        return SecretRule(
            id="postgres-uri-with-password", name="Postgres URI with password",
            pattern=re.compile(r"""postgres(ql)?://[^:]+:[^@]+@[^"'\s]+"""),
            severity=Severity.HIGH, description="Пароль в Postgres URI",
            recommendation="Вынесите пароль в конфигурацию окружения"
        )

    @staticmethod
    def github_token() -> SecretRule:
        return SecretRule(
            id="github-token", name="GitHub token",
            pattern=re.compile(r"""gh[pousr]_[A-Za-z0-9]{36,}"""),
            severity=Severity.CRITICAL, description="GitHub-токен в коде",
            recommendation="Отзовите токен в GitHub Settings → Tokens"
        )

    @staticmethod
    def generic_secret_assignment() -> SecretRule:
        return SecretRule(
            id="generic-secret-assignment", name="Generic secret assignment",
            pattern=re.compile(r"""(?i)(secret|token|key|credential)\s*[:=]\s*["']([A-Za-z0-9_\-./+=]{16,})["']"""),
            severity=Severity.MEDIUM, description="Возможный секрет в коде",
            recommendation="Проверьте значение и вынесите в безопасное хранилище",
            allowlist=[re.compile(r"""(?i)(secret|token|key|credential)\s*[:=]\s*["'](\$\{[^}]+\}|your[-_]?.*|example|dummy|changeme)["']""")]
        )