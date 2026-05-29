"""Unit tests for tools/ftp_pull.py — pure logic, no hardware / no socket.

Run with:
    python3 -m unittest tests/test_ftp_pull.py
"""
import os
import sys
import unittest

# Make both the repo root and tools/ importable.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, 'tools'))

import ftp_pull as fp  # noqa: E402


class TestListParser(unittest.TestCase):
    def test_directory_line(self):
        e = fp.parse_list_line(
            'drw------- 1 user group 0 May 15 03:07 VIDEO')
        self.assertIsNotNone(e)
        self.assertTrue(e.is_dir)
        self.assertEqual(e.name, 'VIDEO')
        self.assertIsNone(e.size)  # dirs carry no meaningful size

    def test_file_line_with_size(self):
        e = fp.parse_list_line(
            '-rw------- 1 user group 268435456 Dec 06 14:15 20251206_141500.MOV')
        self.assertIsNotNone(e)
        self.assertFalse(e.is_dir)
        self.assertEqual(e.name, '20251206_141500.MOV')
        self.assertEqual(e.size, 268435456)

    def test_total_header_skipped(self):
        self.assertIsNone(fp.parse_list_line('total 4'))
        self.assertIsNone(fp.parse_list_line('TOTAL 12'))

    def test_blank_and_dot_entries_skipped(self):
        self.assertIsNone(fp.parse_list_line(''))
        self.assertIsNone(fp.parse_list_line('   '))
        self.assertIsNone(fp.parse_list_line(
            'drwx------ 1 user group 0 May 15 03:07 .'))
        self.assertIsNone(fp.parse_list_line(
            'drwx------ 1 user group 0 May 15 03:07 ..'))

    def test_too_few_tokens_skipped(self):
        self.assertIsNone(fp.parse_list_line('garbage line'))
        self.assertIsNone(fp.parse_list_line('one two three'))

    def test_unparseable_size_is_none_not_crash(self):
        e = fp.parse_list_line(
            '-rw------- 1 user group NOTANUM Dec 06 14:15 weird.MOV')
        self.assertIsNotNone(e)
        self.assertFalse(e.is_dir)
        self.assertEqual(e.name, 'weird.MOV')
        self.assertIsNone(e.size)

    def test_name_with_spaces(self):
        e = fp.parse_list_line(
            'drw------- 1 user group 0 May 15 03:07 System Volume Information')
        self.assertIsNotNone(e)
        self.assertTrue(e.is_dir)
        self.assertEqual(e.name, 'System Volume Information')

    def test_never_raises_on_junk(self):
        for junk in ['\x00\x01', '---', 'd', '   total', '\t\t', 'd x y']:
            # Must return something (None or an entry), never raise.
            fp.parse_list_line(junk)


class TestPathHelpers(unittest.TestCase):
    def test_join_remote(self):
        self.assertEqual(fp.join_remote('/', 'VIDEO'), '/VIDEO')
        self.assertEqual(fp.join_remote('', 'VIDEO'), '/VIDEO')
        self.assertEqual(fp.join_remote('/VIDEO', 'a.MOV'), '/VIDEO/a.MOV')
        self.assertEqual(fp.join_remote('/VIDEO/', 'a.MOV'), '/VIDEO/a.MOV')

    def test_normalize_remote(self):
        self.assertEqual(fp.normalize_remote('/'), '/')
        self.assertEqual(fp.normalize_remote(''), '/')
        self.assertEqual(fp.normalize_remote('/VIDEO/'), '/VIDEO')
        self.assertEqual(fp.normalize_remote('//VIDEO//x'), '/VIDEO/x')

    def test_local_path_mapping(self):
        self.assertEqual(
            fp.local_path_for('/tmp/r', '/VIDEO/x.MOV'),
            os.path.join('/tmp/r', 'VIDEO', 'x.MOV'))
        self.assertEqual(fp.local_path_for('/tmp/r', '/'), '/tmp/r')

    def test_local_path_no_escape(self):
        # '..' / absolute components must never escape dest.
        p = fp.local_path_for('/tmp/r', '/../../etc/passwd')
        self.assertTrue(os.path.abspath(p).startswith('/tmp/r'))
        p2 = fp.local_path_for('/tmp/r', '/VIDEO/../../../../etc/x')
        self.assertTrue(os.path.abspath(p2).startswith('/tmp/r'))


class TestResumeDecision(unittest.TestCase):
    def test_resume_off_never_skips(self):
        self.assertFalse(fp.should_skip(100, 100, resume=False))

    def test_no_local_file_never_skips(self):
        self.assertFalse(fp.should_skip(100, None, resume=True))

    def test_matching_size_skips(self):
        self.assertTrue(fp.should_skip(100, 100, resume=True))

    def test_mismatched_size_redownloads(self):
        self.assertFalse(fp.should_skip(100, 50, resume=True))

    def test_unknown_remote_size_skips_nonempty_local(self):
        self.assertTrue(fp.should_skip(None, 42, resume=True))
        self.assertFalse(fp.should_skip(None, 0, resume=True))


class TestWalkLoopGuard(unittest.TestCase):
    def _make_puller(self):
        return fp.FtpPuller(
            host='x', bind=None, timeout=1.0, retries=1, backoff=0.0,
            sleep=0.0, reconnect_every=0, dest='/tmp/none',
            includes=[], excludes=[], resume=True, dry_run=True,
            verbose=False)

    def test_walk_terminates_and_visits_each_dir_once(self):
        puller = self._make_puller()
        listed: list[str] = []

        # Fake topology with a self-reference (/A -> /A) and a back-edge
        # (/A/B -> /). A naive walk would loop forever.
        tree = {
            '/': [('A', True), ('root.txt', False)],
            '/A': [('A', True), ('B', True), ('a.MOV', False)],
            '/A/B': [('', None)],  # placeholder; real entries built below
        }
        tree['/A/B'] = [('b.MOV', False), ('back', True)]

        def fake_list_dir(path):
            listed.append(path)
            out = []
            for name, is_dir in tree.get(path, []):
                if is_dir is None:
                    continue
                if path == '/A' and name == 'A':
                    child = '/A'           # self-reference
                elif path == '/A/B' and name == 'back':
                    child = '/'            # back-edge to root
                else:
                    child = fp.join_remote(path, name)
                out.append(fp.RemoteEntry(path=child, name=name,
                                          is_dir=is_dir, size=None))
            return out

        puller._list_dir = fake_list_dir
        files = list(puller.walk('/'))

        # Each real dir listed exactly once despite the cycles.
        self.assertEqual(sorted(set(listed)), ['/', '/A', '/A/B'])
        self.assertEqual(len(listed), len(set(listed)),
                         "a directory was listed more than once")
        names = sorted(e.name for e in files)
        self.assertEqual(names, ['a.MOV', 'b.MOV', 'root.txt'])


class TestCrossCheck(unittest.TestCase):
    def test_classification(self):
        results = [
            fp.FileResult('/VIDEO/a.MOV', 100, 'downloaded', bytes_written=100),
            fp.FileResult('/VIDEO/b.MOV', 200, 'skipped-resume'),
            fp.FileResult('/VIDEO/c.MOV', 50, 'downloaded', bytes_written=50),
            fp.FileResult('/VIDEO/x.MOV', None, 'failed'),  # not counted as got
        ]
        ptp_inv = {
            'a.MOV': 100,    # matches
            'b.MOV': 200,    # matches
            'c.MOV': 999,    # size mismatch
            'd.MOV': 300,    # in PTP, missing from mirror
            'e.MOV': 0,      # 0-byte, LIST-hidden, absent
        }
        rep = fp.cross_check(results, ptp_inv)
        self.assertEqual(rep['ptp_count'], 5)
        self.assertEqual(rep['matched'], 3)  # a, b, c present (c size-bad)
        self.assertEqual([m['name'] for m in rep['missing_from_mirror']],
                         ['d.MOV'])
        self.assertEqual([m['name'] for m in rep['size_mismatch']], ['c.MOV'])
        self.assertEqual(rep['empty_list_hidden'], ['e.MOV'])


class TestBuildInventory(unittest.TestCase):
    def test_merge_three_sources(self):
        ftp_dirs = ['/', '/VIDEO', '/JPG']          # root must be dropped
        ftp_files = [
            fp.RemoteEntry('/VIDEO/a.MOV', 'a.MOV', False, 100),
            fp.RemoteEntry('/FACTORY.RUN', 'FACTORY.RUN', False, 512),
        ]
        size_hits = {'/SPHOST.BRN': 0, '/FACTORY.RUN': 512}  # SPHOST is hidden
        ptp_inv = {'a.MOV': 100, 'b.MOV': 200}              # b.MOV is PTP-only
        items = {it.path: it for it in
                 fp.build_inventory(ftp_files, ftp_dirs, size_hits, ptp_inv)}

        self.assertNotIn('/', items)                        # root excluded
        self.assertTrue(items['/JPG'].is_dir)
        self.assertEqual(items['/JPG'].sources, ['list'])

        # read-only/hidden: only SIZE-probe found it
        sphost = items['/SPHOST.BRN']
        self.assertEqual(sphost.sources, ['size'])
        self.assertEqual(sphost.size, 0)
        self.assertIn('read-only', fp._inv_note(sphost))

        # listed AND size-probed
        self.assertEqual(sorted(items['/FACTORY.RUN'].sources),
                         ['list', 'size'])

        # listed AND in PTP
        self.assertEqual(sorted(items['/VIDEO/a.MOV'].sources),
                         ['list', 'ptp'])

        # PTP-only media the FTP view missed
        b = items['/b.MOV']
        self.assertEqual(b.sources, ['ptp'])
        self.assertEqual(b.size, 200)
        self.assertIn('PTP-only', fp._inv_note(b))


if __name__ == '__main__':
    unittest.main()
