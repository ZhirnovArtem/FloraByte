from security_scanners.sca.parser import GradleDependencyParser

def test_parses_quoted_dependencies():
    content = 'dependencies {\n    implementation("org.springframework.boot:spring-boot-starter-web:3.1.0")\n}'
    deps = GradleDependencyParser().parse(content, "build.gradle.kts")
    assert len(deps) == 1
    assert deps[0].package_name == "org.springframework.boot:spring-boot-starter-web"

def test_skips_dynamic_versions():
    content = 'implementation("com.example:lib:1.0.+")'
    deps = GradleDependencyParser().parse(content, "build.gradle.kts")
    assert deps == []