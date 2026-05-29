"""Unit tests for tools/sync_recovered.py — pure logic only (no ssh/hardware)."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tools'))
import sync_recovered as s  # noqa: E402


class TestParseRemoteFind(unittest.TestCase):
    def test_basic(self):
        text = "a.jpg\t100\nsub/b.jpg\t250\n"
        self.assertEqual(s.parse_remote_find(text),
                         {'a.jpg': 100, 'sub/b.jpg': 250})

    def test_skips_blank_and_malformed(self):
        text = "\nok.jpg\t10\nno_tab_here\nbad\tNaN\n"
        out = s.parse_remote_find(text)
        self.assertEqual(out['ok.jpg'], 10)
        self.assertEqual(out['bad'], 0)        # unparseable size -> 0
        self.assertNotIn('no_tab_here', out)   # no size field -> dropped
        self.assertNotIn('', out)

    def test_paths_with_spaces(self):
        text = "Shot foo/Camera 1/frame_x.jpg\t42\n"
        self.assertEqual(s.parse_remote_find(text),
                         {'Shot foo/Camera 1/frame_x.jpg': 42})


class TestCompare(unittest.TestCase):
    def test_three_states(self):
        local = {'both.jpg': 1, 'localonly.jpg': 2}
        remote = {'both.jpg': 1, 'remoteonly.jpg': 3}
        rows = s.compare(local, remote)
        status = dict(rows)
        self.assertEqual(status['both.jpg'], 'both')
        self.assertEqual(status['localonly.jpg'], 'local')
        self.assertEqual(status['remoteonly.jpg'], 'remote')

    def test_sorted_by_path(self):
        rows = s.compare({'z': 1, 'a': 1}, {'m': 1})
        self.assertEqual([r[0] for r in rows], ['a', 'm', 'z'])

    def test_size_ignored_for_status(self):
        # presence-based: same path, different size is still 'both'
        rows = s.compare({'x': 1}, {'x': 999})
        self.assertEqual(rows, [('x', 'both')])

    def test_empty(self):
        self.assertEqual(s.compare({}, {}), [])


class TestCountStatus(unittest.TestCase):
    def test_counts(self):
        rows = [('a', 'both'), ('b', 'both'), ('c', 'remote'), ('d', 'local')]
        c = s.count_status(rows)
        self.assertEqual(c['both'], 2)
        self.assertEqual(c['remote'], 1)
        self.assertEqual(c['local'], 1)
        self.assertEqual(c.get('missing', 0), 0)


class TestColorize(unittest.TestCase):
    def test_color_wraps_with_reset(self):
        out = s.colorize('hi', s.C_RED, use_color=True)
        self.assertTrue(out.startswith(s.C_RED))
        self.assertTrue(out.endswith(s.RESET))
        self.assertIn('hi', out)

    def test_no_color_is_plain(self):
        self.assertEqual(s.colorize('hi', s.C_RED, use_color=False), 'hi')


class TestResolveConfig(unittest.TestCase):
    BUILTIN = {'host': '', 'user': 'micah',
               'remote_base': '/r', 'local_base': '~/l'}

    def test_cli_wins_over_everything(self):
        out = s.resolve_config(
            cli={'host': 'cli'}, env={'host': 'env'},
            file_cfg={'host': 'file'}, builtin=self.BUILTIN)
        self.assertEqual(out['host'], 'cli')

    def test_env_beats_file_and_builtin(self):
        out = s.resolve_config(
            cli={'host': None}, env={'host': 'env'},
            file_cfg={'host': 'file'}, builtin=self.BUILTIN)
        self.assertEqual(out['host'], 'env')

    def test_file_beats_builtin(self):
        out = s.resolve_config(
            cli={}, env={}, file_cfg={'host': 'file'}, builtin=self.BUILTIN)
        self.assertEqual(out['host'], 'file')

    def test_empty_values_fall_through(self):
        # empty string / None are "absent" and must not shadow later sources
        out = s.resolve_config(
            cli={'host': ''}, env={'host': None},
            file_cfg={'host': ''}, builtin={'host': 'fallback'})
        self.assertEqual(out['host'], 'fallback')

    def test_no_host_baked_into_builtin(self):
        # guards the sanitary invariant: the script ships with no host IP
        self.assertEqual(s.BUILTIN['host'], '')

    def test_user_and_bases_default_from_builtin(self):
        out = s.resolve_config(cli={}, env={}, file_cfg={}, builtin=self.BUILTIN)
        self.assertEqual(out['user'], 'micah')
        self.assertEqual(out['remote_base'], '/r')
        self.assertEqual(out['host'], '')


class TestConfigRoundTrip(unittest.TestCase):
    def test_save_then_load(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'sub', 'config.json')
            s.save_config(path, {'host': '10.0.0.5', 'user': 'bob',
                                 'remote_base': '/r', 'local_base': '~/l',
                                 'ignored': 'nope'})
            loaded = s.load_config(path)
            self.assertEqual(loaded['host'], '10.0.0.5')
            self.assertEqual(loaded['user'], 'bob')
            self.assertNotIn('ignored', loaded)  # only known keys persisted

    def test_load_missing_is_empty(self):
        self.assertEqual(s.load_config('/no/such/config.json'), {})

    def test_load_corrupt_is_empty(self):
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as fh:
            fh.write('{ not valid json')
            bad = fh.name
        try:
            self.assertEqual(s.load_config(bad), {})
        finally:
            os.unlink(bad)

    def test_save_drops_empty_values(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'config.json')
            s.save_config(path, {'host': 'h', 'user': '', 'remote_base': '',
                                 'local_base': ''})
            self.assertEqual(s.load_config(path), {'host': 'h'})


if __name__ == '__main__':
    unittest.main()
