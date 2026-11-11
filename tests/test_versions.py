import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))

from cvescan_core import versions as V  # noqa: E402


class CompareTest(unittest.TestCase):
    def test_basic_order(self):
        self.assertEqual(V.compare("1.2.3", "1.2.10"), -1)
        self.assertEqual(V.compare("v1.2.0", "1.2"), 0)
        self.assertEqual(V.compare("2.0.0", "1.99.99"), 1)

    def test_prerelease_and_post(self):
        self.assertEqual(V.compare("1.0.0-rc.1", "1.0.0"), -1)
        self.assertEqual(V.compare("1.0.0-alpha", "1.0.0-beta"), -1)
        self.assertEqual(V.compare("1.0.dev1", "1.0a1"), -1)
        self.assertEqual(V.compare("1.0.post1", "1.0"), 1)
        self.assertEqual(V.compare("1.0.0-p1", "1.0.0"), 1)

    def test_unparseable(self):
        self.assertIsNone(V.compare("dev-main", "1.0.0"))

    def test_sort(self):
        self.assertEqual(
            V.sort_versions(["4.17.21", "4.17.19", "dev-main", "4.2.0"]),
            ["4.2.0", "4.17.19", "4.17.21", "dev-main"],
        )


class NpmRangeTest(unittest.TestCase):
    def check(self, version, rng, expected):
        self.assertEqual(V.npm_satisfies(version, rng), expected, f"{version} in {rng!r}")

    def test_caret(self):
        self.check("4.17.21", "^4.17.15", True)
        self.check("5.0.0", "^4.17.15", False)
        self.check("0.2.5", "^0.2.3", True)
        self.check("0.3.0", "^0.2.3", False)
        self.check("0.0.4", "^0.0.3", False)
        self.check("1.9.0", "^1.x", True)

    def test_tilde(self):
        self.check("1.2.9", "~1.2.3", True)
        self.check("1.3.0", "~1.2.3", False)
        self.check("1.9.0", "~1", True)

    def test_exact_and_partial(self):
        self.check("6.7.3", "6.7.0", False)
        self.check("6.7.0", "6.7.0", True)
        self.check("1.2.7", "1.2.x", True)
        self.check("1.3.0", "1.2", False)
        self.check("9.9.9", "*", True)

    def test_comparators_and_or(self):
        self.check("1.5.0", ">=1.2.0 <2.0.0", True)
        self.check("2.0.0", ">=1.2.0 <2.0.0", False)
        self.check("3.1.0", "^1.0.0 || ^3.0.0", True)
        self.check("2.1.0", "^1.0.0 || ^3.0.0", False)
        self.check("1.5.0", "1.2.3 - 2.3.4", True)
        self.check("2.3.5", "1.2.3 - 2.3", True)
        self.check("1.3.0", ">1.2", True)
        self.check("1.2.9", ">1.2", False)

    def test_unknown(self):
        self.check("1.0.0", "npm:other@^1.0.0", None)
        self.check("1.0.0", "github:user/repo", None)
        self.check("1.0.0", "workspace:*", None)


class ComposerRangeTest(unittest.TestCase):
    def check(self, version, rng, expected):
        self.assertEqual(V.composer_satisfies(version, rng), expected, f"{version} in {rng!r}")

    def test_caret_tilde(self):
        self.check("7.4.3", "^7.4", True)
        self.check("8.0.0", "^7.4", False)
        self.check("1.9.0", "~1.2", True)       # composer: ~1.2 means >=1.2 <2.0
        self.check("2.0.0", "~1.2", False)
        self.check("1.2.9", "~1.2.3", True)
        self.check("1.3.0", "~1.2.3", False)

    def test_or_and_wildcard(self):
        self.check("2.1.1", "^1.8.3 || ^2.1", True)
        self.check("v2.1.1", "^1.8.3|^2.1", True)
        self.check("2.0.5", "^1.8.3 || ^2.1", False)
        self.check("1.0.7", "1.0.*", True)
        self.check("1.1.0", "1.0.*", False)
        self.check("1.5.0", ">=1.0 <2.0", True)
        self.check("1.5.0", ">=1.0,<1.4", False)
        self.check("1.2.0", "1.2", True)

    def test_unknown(self):
        self.check("1.0.0", "dev-main", None)


class Pep440Test(unittest.TestCase):
    def check(self, version, spec, expected):
        self.assertEqual(V.pep440_satisfies(version, spec), expected, f"{version} in {spec!r}")

    def test_specifiers(self):
        self.check("3.1.3", ">=3.0", True)
        self.check("3.1.3", ">=3.0,<3.1", False)
        self.check("2.20.0", "==2.*", True)
        self.check("3.0.0", "==2.*", False)
        self.check("1.4.5", "~=1.4.2", True)
        self.check("1.5.0", "~=1.4.2", False)
        self.check("1.9", "~=1.4", True)
        self.check("2.0", "~=1.4", False)
        self.check("1.0", "!=1.0", False)
        self.check("9.9", "*", True)


class SelectFixTest(unittest.TestCase):
    def test_interval(self):
        ranges = [
            [{"introduced": "0"}, {"fixed": "6.5.6"}],
            [{"introduced": "7.0.0"}, {"fixed": "7.4.3"}],
        ]
        self.assertEqual(V.select_fix("7.4.2", ranges), ("7.4.3", ["7.4.3"]))
        self.assertEqual(V.select_fix("6.5.5", ranges), ("6.5.6", ["6.5.6", "7.4.3"]))

    def test_many_branches(self):
        ranges = [
            [{"introduced": "6.7.0"}, {"fixed": "6.7.3"}],
            [{"introduced": "6.8.0"}, {"fixed": "6.8.3"}],
            [{"introduced": "0"}, {"fixed": "6.2.4"}],
        ]
        recommended, fixed = V.select_fix("6.7.0", ranges)
        self.assertEqual(recommended, "6.7.3")
        self.assertEqual(fixed, ["6.7.3", "6.8.3"])

    def test_no_fix(self):
        ranges = [[{"introduced": "0"}, {"last_affected": "4.5.0"}]]
        self.assertEqual(V.select_fix("4.5.0", ranges), (None, []))


if __name__ == "__main__":
    unittest.main()
