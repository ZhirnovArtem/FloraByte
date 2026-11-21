import re
from ..context import FileContext
from ..model import Severity, Confidence
from .base import Rule
from .spring_analysis import (
    detect_cors_wildcard,
    detect_object_authorization,
    detect_route_authorization,
    detect_sql_injection,
    detect_tls_verification,
)


def hits(ctx: FileContext, pattern: str, *, flags=re.I|re.S, exclude: str|None=None):
    text = ctx.code
    out=[]
    for m in re.finditer(pattern, text, flags):
        snippet=m.group(0)
        if exclude and re.search(exclude, snippet, re.I|re.S):
            continue
        pos=m.start(); line=text.count('\n',0,pos)+1
        col=pos-(text.rfind('\n',0,pos)+1)+1
        out.append((line,col,snippet,"Конструкция обнаружена в исполняемом тексте; точность зависит от контекста вызова."))
    return out

def cfg(ctx: FileContext, pattern: str):
    out=[]
    for m in re.finditer(pattern, ctx.code, re.I|re.M):
        pos=m.start(); line=ctx.code.count('\n',0,pos)+1
        col=pos-(ctx.code.rfind('\n',0,pos)+1)+1
        sev="dev/local/test" if ctx.profile in {"dev","local","test"} else "непрофильная конфигурация"
        out.append((line,col,m.group(0),f"Параметр конфигурации задан небезопасно; профиль: {sev}."))
    return out

RULES = [
 Rule("SAST-SEC-001","CWE-862","Открытый доступ к защищаемым маршрутам",Severity.HIGH,Confidence.HIGH,
      "permitAll() применяется к широкому или защищаемому правилу доступа; проверьте авторизацию маршрута.",
      "Заменить широкое разрешение на authenticated()/hasRole() и открывать только публичные маршруты без чувствительных данных.",
      detect_route_authorization),
 Rule("SAST-SEC-002","CWE-352","Отключена CSRF-защита",Severity.MEDIUM,Confidence.HIGH,
      "CSRF-защита отключена. Это опасно для браузерных сессий; для stateless API требуется отдельное обоснование.",
      "Не отключать CSRF для cookie/session-аутентификации; для stateless API документировать модель аутентификации и отключать точечно.",
      lambda c: hits(c,r"csrf\s*(?:\{[^}]*?disable\s*\(\s*\)[^}]*?\}|\(\s*\)\s*\.\s*disable\s*\(\s*\))")),
 Rule("SAST-SEC-003","CWE-942","Разрешён wildcard-origin в CORS",Severity.HIGH,Confidence.HIGH,
      "CORS разрешает произвольный origin; при включённых credentials риск существенно выше.",
      "Задать точный список доверенных origin и не сочетать wildcard с allowCredentials=true.",
      detect_cors_wildcard),
 Rule("SAST-SEC-005","CWE-256","Небезопасное хранение пароля",Severity.HIGH,Confidence.HIGH,
      "Используется NoOpPasswordEncoder, {noop} или слабый хэш для хранения пароля.",
      "Использовать BCryptPasswordEncoder, Argon2PasswordEncoder или DelegatingPasswordEncoder.",
      lambda c: hits(c,r"(?:NoOpPasswordEncoder|\{noop\}|MessageDigest\.getInstance\s*\(\s*\"(?:MD5|SHA-1)\"\s*\))")),
 Rule("SAST-TLS-001","CWE-295","Отключена проверка TLS-сертификата или hostname",Severity.HIGH,Confidence.HIGH,
      "Используется HostnameVerifier или TrustManager, принимающий любые сертификаты/хосты.",
      "Использовать штатную проверку сертификатов и имени хоста JVM/HTTPS-клиента.",
      detect_tls_verification),
 Rule("SAST-INJ-001","CWE-89","Возможная SQL-инъекция",Severity.HIGH,Confidence.HIGH,
      "SQL формируется интерполяцией или конкатенацией в вызове JDBC/native query; используйте параметризованные запросы.",
      "Использовать PreparedStatement/параметры '?' вместо интерполяции строк.",
      detect_sql_injection),
 Rule("SAST-INJ-002","CWE-78","Возможная инъекция команд ОС",Severity.HIGH,Confidence.MEDIUM,
      "Команда ОС строится из динамического значения; если оно контролируется запросом, возможна command injection.",
      "Не передавать пользовательские данные в shell; использовать фиксированный executable и аргументы с allowlist.",
      lambda c: hits(c,r"(?:Runtime\.getRuntime\s*\(\s*\)\s*\.\s*exec|ProcessBuilder)\s*\([^\n;]{0,240}(?:\$\w+|\$\{|\s\+\s|request\.)")),
 Rule("SAST-AUTH-001","CWE-639","Отсутствует проверка владельца объекта (IDOR/BOLA)",Severity.HIGH,Confidence.HIGH,
      "Метод чтения объекта фильтрует запись только по идентификатору без проверки принадлежности текущему пользователю.",
      "Передавать идентификатор текущего пользователя (Principal) и фильтровать выборку по владельцу объекта.",
      detect_object_authorization),
 Rule("SAST-CRY-001","CWE-327","Используется слабый криптографический хэш",Severity.MEDIUM,Confidence.HIGH,
      "MD5/SHA-1 используются как криптографический хэш. Для паролей и защитных токенов такие алгоритмы неприемлемы.",
      "Для паролей использовать Argon2/BCrypt; для целостности — SHA-256 или современный алгоритм по назначению.",
      lambda c: hits(c,r"(?:MessageDigest\.getInstance\s*\(\s*\"(?:MD5|SHA-1)\"|DigestUtils\.(?:md5|sha1)Hex)")),
 Rule("SAST-CFG-001","CWE-200","Открыта публикация management endpoints",Severity.HIGH,Confidence.HIGH,
      "Actuator endpoints раскрываются через wildcard exposure; проверьте доступность извне.",
      "Ограничить exposure.include конкретными endpoint и защитить их аутентификацией/сетевыми правилами.",
      lambda c: cfg(c,r"management\.endpoints\.web\.exposure\.include\s*[:=]\s*\*")),
 Rule("SAST-CFG-002","CWE-489","Включена H2 console с внешним доступом",Severity.HIGH,Confidence.HIGH,
      "H2 console включена и разрешает доступ извне; настройка не должна присутствовать в production.",
      "Отключить H2 console вне локальной разработки и не разрешать web-others.",
      lambda c: cfg(c,r"(?:spring\.h2\.console\.enabled\s*[:=]\s*true|spring\.h2\.console\.settings\.web-allow-others\s*[:=]\s*true)")),
 Rule("SAST-LOG-001","CWE-532","Возможна запись чувствительных данных в лог",Severity.MEDIUM,Confidence.MEDIUM,
      "В лог передаётся переменная с именем, похожим на пароль, токен или секрет.",
      "Маскировать значения до логирования; не логировать credentials и authorization headers.",
      lambda c: hits(c,r"(?:logger\.(?:info|debug|warn|error)|println)\s*\([^\n)]{0,200}(?:password|passwd|token|secret|authorization)\w*")),
]
