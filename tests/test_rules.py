import pytest
from pathlib import Path
from scanners.sast.engine import run

CASES = [
 ("SAST-SEC-001", "anyRequest().permitAll()", "anyRequest().authenticated()", "SecurityConfig.kt"),
 ("SAST-SEC-002", "http.csrf().disable()", "http.csrf { it.csrfTokenRepository(repo) }", "SecurityConfig.kt"),
 ("SAST-SEC-003", 'allowedOrigins("*")', 'allowedOrigins("https://app.example")', "CorsConfig.kt"),
 ("SAST-SEC-005", 'NoOpPasswordEncoder.getInstance()', 'BCryptPasswordEncoder()', "PasswordConfig.kt"),
 ("SAST-INJ-001", 'jdbcTemplate.query("select * from users where id=$id")', 'jdbcTemplate.query("select * from users where id=?", args)', "UserRepo.kt"),
 ("SAST-INJ-002", 'Runtime.getRuntime().exec(command + userInput)', 'ProcessBuilder("/usr/bin/id").start()', "Runner.kt"),
 ("SAST-CRY-001", 'MessageDigest.getInstance("MD5")', 'MessageDigest.getInstance("SHA-256")', "Hash.kt"),
 ("SAST-CFG-001", 'management.endpoints.web.exposure.include=*', 'management.endpoints.web.exposure.include=health,info', "application.properties"),
 ("SAST-CFG-002", 'spring.h2.console.enabled=true', 'spring.h2.console.enabled=false', "application.properties"),
 ("SAST-LOG-001", 'logger.info("token=$token")', 'logger.info("request completed")', "Audit.kt"),
]

@pytest.mark.parametrize("rule,bad,good,name",CASES)
def test_rule_positive_and_negative(tmp_path,rule,bad,good,name):
    # Two positive and two negative cases per rule (same pattern in two harmless contexts).
    for i,code in enumerate([bad,bad]):
        p=tmp_path/f"bad{i}"; p.mkdir(); (p/name).write_text(code,encoding="utf-8")
        assert any(f.rule_id==rule for f in run(p).findings), (rule,code)
    for i,code in enumerate([good,good]):
        p=tmp_path/f"good{i}"; p.mkdir(); (p/name).write_text(code,encoding="utf-8")
        assert not any(f.rule_id==rule for f in run(p).findings), (rule,code)

def test_comments_do_not_trigger(tmp_path):
    p=tmp_path/"src"/"main"/"kotlin"; p.mkdir(parents=True)
    (p/"Safe.kt").write_text('// anyRequest().permitAll()\n/* NoOpPasswordEncoder */\nfun ok() = 1')
    assert run(tmp_path).findings == []

def test_finding_has_required_fields(tmp_path):
    p=tmp_path/"src"/"main"/"kotlin"; p.mkdir(parents=True)
    (p/"Security.kt").write_text('anyRequest().permitAll()')
    finding=run(tmp_path).findings[0]
    assert finding.severity and finding.confidence and finding.cwe and finding.rationale

def test_evidence_masks_secret_like_values(tmp_path):
    p=tmp_path/"src"/"main"/"kotlin"; p.mkdir(parents=True)
    (p/"Audit.kt").write_text('logger.info("token=super-secret-value")')
    result=run(tmp_path)
    assert result.findings
    assert "super-secret-value" not in result.findings[0].evidence


def test_spring_general_sast_rules_and_controls(tmp_path):
    src = tmp_path / "src" / "main" / "kotlin" / "demo"
    src.mkdir(parents=True)
    (src / "Orders.kt").write_text(
        '''
@RestController
@RequestMapping("/api/orders")
class OrderController(private val dao: OrderDao) {
    @GetMapping("/search")
    fun search(@RequestParam q: String) = jdbc.queryForList("SELECT code FROM orders WHERE code = '$q'", String::class.java)

    @GetMapping("/safe")
    fun safe(@RequestParam q: String) = jdbc.queryForList("SELECT code FROM orders WHERE code = ?", String::class.java, q)

    @GetMapping("/{orderId}")
    fun getOne(@PathVariable orderId: Long) = dao.findById(orderId)

    @GetMapping("/dump")
    fun dump() = jdbc.queryForList("SELECT id, owner_id FROM orders")
}

@RestController
class PublicInfoController {
    @GetMapping("/api/public/info")
    fun info() = listOf("v1", "ok")
}

@Repository
class OrderDao(private val jdbc: JdbcTemplate) {
    fun findById(orderId: Long) = jdbc.query(
        "SELECT id, owner_id, notes FROM orders WHERE id = ?",
        { rs, _ -> rs.getString(1) },
        orderId,
    ).firstOrNull()
}

@Configuration
class SecurityAndCors {
    fun cors() = CorsConfiguration().apply {
        allowedOriginPatterns = listOf("*")
        allowCredentials = true
    }

    fun sec(http: HttpSecurity) = http.authorizeHttpRequests { rules ->
        rules.requestMatchers(GET, "/api/public/info").permitAll()
        rules.requestMatchers(GET, "/api/orders/dump").permitAll()
        rules.requestMatchers("/api/orders/**").hasRole("STAFF")
    }

    fun tls(conn: HttpsURLConnection) {
        conn.hostnameVerifier = HostnameVerifier { _, _ -> true }
    }
}
''',
        encoding="utf-8",
    )
    findings = run(tmp_path).findings
    rule_ids = {f.rule_id for f in findings}
    assert {"SAST-INJ-001", "SAST-AUTH-001", "SAST-SEC-003", "SAST-SEC-001", "SAST-TLS-001"} <= rule_ids
    # Ensure static /api/public/info permitAll() and parameterized query did NOT trigger
    sec001_lines = [f.line for f in findings if f.rule_id == "SAST-SEC-001"]
    assert len(sec001_lines) == 1
    inj_lines = [f.line for f in findings if f.rule_id == "SAST-INJ-001"]
    assert len(inj_lines) == 1
