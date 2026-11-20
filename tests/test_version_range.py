from security_scanners.sca.version_range import VersionRange, compare_versions

def test_in_range_2_14_0():
    assert VersionRange.in_range("2.14.0", ">=2.0.0 <2.15.0")

def test_not_in_range_2_15_0():
    assert not VersionRange.in_range("2.15.0", ">=2.0.0 <2.15.0")

def test_2_9_less_than_2_10():
    assert compare_versions("2.9.0", "2.10.0") < 0

def test_2_13_2_0_in_range():
    assert VersionRange.in_range("2.13.2.0", ">=2.0.0 <2.13.2.1")