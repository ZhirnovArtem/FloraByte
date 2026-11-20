from adapters.scanner1_fixture import Scanner1FixtureAdapter, load_fixture
from adapters.scanner2_fixture import Scanner2FixtureAdapter
from contracts.adapters import AdapterError

raw1 = load_fixture("fixtures/scanner1/sample.json")
r1 = Scanner1FixtureAdapter().normalize(raw1)
print("scanner1 count:", len(r1))
print("scanner1 first:", r1[0])

raw2 = load_fixture("fixtures/scanner2/sample.json")
r2 = Scanner2FixtureAdapter().normalize(raw2)
print("scanner2 count:", len(r2))
print("scanner2 severities:", r2[0]["severity"], r2[1]["severity"])

try:
    Scanner1FixtureAdapter().normalize({"issues": []})
except AdapterError as e:
    print("fixture guard ok:", str(e)[:60])
else:
    print("fixture guard FAILED: no error")