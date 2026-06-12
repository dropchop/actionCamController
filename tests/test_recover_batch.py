"""Unit tests for tools/recover_batch.py — pure logic, no hardware / sudo.

Run with:
    python3 -m unittest tests/test_recover_batch.py
"""
import os
import sys
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, 'tools'))

import recover_batch as rb  # noqa: E402


class TestParseSelection(unittest.TestCase):
    def test_all_aliases(self):
        for s in ('all', 'ALL', 'a', '*'):
            self.assertEqual(rb.parse_selection(s, 3), [0, 1, 2])

    def test_comma_and_space(self):
        self.assertEqual(rb.parse_selection('1,3,4', 4), [0, 2, 3])
        self.assertEqual(rb.parse_selection('1 3 4', 4), [0, 2, 3])
        self.assertEqual(rb.parse_selection('1, 3 ,4', 4), [0, 2, 3])

    def test_ranges(self):
        self.assertEqual(rb.parse_selection('1-3', 5), [0, 1, 2])
        self.assertEqual(rb.parse_selection('1-2,4', 5), [0, 1, 3])

    def test_dedup_and_sort(self):
        self.assertEqual(rb.parse_selection('3,1,1,2', 3), [0, 1, 2])
        self.assertEqual(rb.parse_selection('2-3,1-2', 3), [0, 1, 2])

    def test_empty_is_empty_list(self):
        self.assertEqual(rb.parse_selection('', 3), [])
        self.assertEqual(rb.parse_selection('   ', 3), [])

    def test_out_of_range_is_none(self):
        self.assertIsNone(rb.parse_selection('0', 3))
        self.assertIsNone(rb.parse_selection('4', 3))
        self.assertIsNone(rb.parse_selection('1,9', 3))

    def test_bad_range_is_none(self):
        self.assertIsNone(rb.parse_selection('3-1', 5))   # reversed
        self.assertIsNone(rb.parse_selection('1-9', 5))   # hi past end
        self.assertIsNone(rb.parse_selection('0-2', 5))   # lo below 1

    def test_garbage_is_none(self):
        self.assertIsNone(rb.parse_selection('abc', 3))
        self.assertIsNone(rb.parse_selection('1,x', 3))


class TestReuseFromRecoverCamera(unittest.TestCase):
    """The batch tool is built on recover_camera's primitives — sanity-check
    that the re-exports it depends on are actually present and behave."""

    def test_derive_dest_sanitizes(self):
        # Reused verbatim for each camera's per-SSID output folder.
        d = rb.derive_dest('/tmp/base', 'ActionCam_C7/../etc')
        self.assertTrue(d.startswith('/tmp/base/'))
        self.assertNotIn('..', d)

    def test_map_pull_rc_known_codes(self):
        self.assertEqual(rb.map_pull_rc(0)[1], 0)
        self.assertEqual(rb.map_pull_rc(2)[1], 2)
        self.assertEqual(rb.map_pull_rc(99)[1], 4)  # unknown -> usage error


if __name__ == '__main__':
    unittest.main()
