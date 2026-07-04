#!/usr/bin/env python3
"""Deterministic test runner.

`python -m unittest discover -s tests -t .` can trip a Windows-specific quirk in
unittest's -m main path (namespace-package __file__=None). This script calls the
loader directly, which is reliable. Usage: `python run_tests.py`.
"""

import sys
import unittest


def main() -> int:
    suite = unittest.TestLoader().discover("tests", pattern="test*.py", top_level_dir=".")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
