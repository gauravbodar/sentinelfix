import unittest

from avmp.benchmark import run_benchmark


class TestBenchmark(unittest.TestCase):
    def test_false_positive_rate_under_5_percent(self):
        result = run_benchmark(n_vulnerable=8, n_clean=20)
        # AC-10: credentialed/networked exposure check FP rate < 5%.
        self.assertLess(result.false_positive_rate, 0.05)
        # And it actually detects the seeded vulnerable hosts.
        self.assertGreaterEqual(result.detection_rate, 0.95)


if __name__ == "__main__":
    unittest.main()
