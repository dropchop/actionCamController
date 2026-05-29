"""Unit tests for tools/recover_camera.py — pure logic, no hardware / sudo.

Run with:
    python3 -m unittest tests/test_recover_camera.py
"""
import os
import sys
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, 'tools'))

import recover_camera as rc  # noqa: E402


class TestParseWifiList(unittest.TestCase):
    def test_terse_bssid_unescaping_and_filter(self):
        # nmcli -t escapes the ':' in BSSIDs as '\:'. Non-ActionCam rows drop.
        text = (
            r"ActionCam_C762D5:00\:E0\:4C\:C7\:62\:D5:80:WPA2" + "\n"
            r"Cool_Guy:BC\:9A\:8E\:ED\:95\:04:100:WPA2" + "\n"
            r"ActionCam_1A80DF:00\:E0\:4C\:1A\:80\:DF:62:WPA2" + "\n"
        )
        cams = rc.parse_wifi_list(text)
        self.assertEqual([c.ssid for c in cams],
                         ['ActionCam_C762D5', 'ActionCam_1A80DF'])  # signal sort
        self.assertEqual(cams[0].bssid, '00:E0:4C:C7:62:D5')
        self.assertEqual(cams[0].signal, 80)
        self.assertEqual(cams[1].signal, 62)

    def test_dedup_keeps_strongest(self):
        text = (
            r"ActionCam_X:00\:11\:22\:33\:44\:55:40:WPA2" + "\n"
            r"ActionCam_X:00\:11\:22\:33\:44\:66:90:WPA2" + "\n"
        )
        cams = rc.parse_wifi_list(text)
        self.assertEqual(len(cams), 1)
        self.assertEqual(cams[0].signal, 90)
        self.assertEqual(cams[0].bssid, '00:11:22:33:44:66')

    def test_blank_and_short_lines_skipped(self):
        text = "\n   \nActionCam_Y:onlytwo\n"
        self.assertEqual(rc.parse_wifi_list(text), [])

    def test_bad_signal_is_zero(self):
        text = r"ActionCam_Z:00\:00\:00\:00\:00\:00:notanum:WPA2"
        cams = rc.parse_wifi_list(text)
        self.assertEqual(cams[0].signal, 0)


class TestSplitTerse(unittest.TestCase):
    def test_unescape(self):
        self.assertEqual(rc._split_terse(r"a:b:c"), ['a', 'b', 'c'])
        self.assertEqual(rc._split_terse(r"x\:y:z"), ['x:y', 'z'])
        self.assertEqual(rc._split_terse(r"00\:E0\:4C"), ['00:E0:4C'])


class TestDeriveDest(unittest.TestCase):
    def test_normal(self):
        self.assertEqual(rc.derive_dest('/base', 'ActionCam_1A80DF'),
                         os.path.join('/base', 'ActionCam_1A80DF'))

    def test_hostile_ssid_cannot_escape(self):
        for evil in ['../../etc', 'a/../../b', '..', '/abs/path', 'x/y']:
            d = rc.derive_dest('/base', evil)
            self.assertTrue(os.path.abspath(d).startswith('/base'),
                            f"{evil!r} escaped to {d}")
        # dots-only must not survive as a traversal token
        self.assertEqual(rc.derive_dest('/base', '..'),
                         os.path.join('/base', '__'))

    def test_empty_ssid(self):
        self.assertEqual(rc.derive_dest('/base', ''),
                         os.path.join('/base', 'camera'))


class TestDongleIp(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(rc.parse_dongle_ip('192.168.1.10/24'), '192.168.1.10')
        self.assertEqual(rc.parse_dongle_ip('192.168.1.10/24\n'), '192.168.1.10')
        self.assertEqual(rc.parse_dongle_ip(''), '')
        self.assertEqual(rc.parse_dongle_ip('\n\n'), '')

    def test_validate(self):
        self.assertTrue(rc.validate_dongle_ip('192.168.1.10'))
        self.assertTrue(rc.validate_dongle_ip('192.168.1.42'))
        self.assertFalse(rc.validate_dongle_ip('192.168.1.1'))    # camera
        self.assertFalse(rc.validate_dongle_ip('192.168.1.254'))  # home GW
        self.assertFalse(rc.validate_dongle_ip('10.0.0.5'))
        self.assertFalse(rc.validate_dongle_ip(''))
        self.assertFalse(rc.validate_dongle_ip('192.168.1.'))


class TestRoutePresent(unittest.TestCase):
    def test_formats(self):
        self.assertTrue(rc.route_present('192.168.1.1/32'))
        self.assertTrue(rc.route_present(
            '{ ip = 192.168.1.1/32, nh = 0.0.0.0 }'))
        self.assertFalse(rc.route_present(''))
        self.assertFalse(rc.route_present('192.168.1.0/24'))


class TestBuildArgv(unittest.TestCase):
    def test_connect_argv(self):
        self.assertEqual(
            rc.build_connect_argv('ActionCam_X', '1234567890', 'wlx0'),
            ['nmcli', 'device', 'wifi', 'connect', 'ActionCam_X',
             'password', '1234567890', 'ifname', 'wlx0'])

    def test_pull_argv_preview(self):
        argv = rc.build_pull_argv(
            'py', '/r/ftp_pull.py', '192.168.1.1', '192.168.1.10',
            '/d', '/d/manifest.json', sleep=0.5, retries=5, backoff=2.0,
            reconnect_every=50, preview=True, ptp_verify=True, verbose=False)
        self.assertIn('--dry-run', argv)
        # ptp-verify must NOT be added in preview mode
        self.assertNotIn('--verify-ptp', argv)
        self.assertEqual(argv[:3], ['py', '/r/ftp_pull.py', '192.168.1.1'])
        self.assertIn('--bind', argv)
        self.assertEqual(argv[argv.index('--bind') + 1], '192.168.1.10')

    def test_pull_argv_real_with_ptp(self):
        argv = rc.build_pull_argv(
            'py', '/r/ftp_pull.py', '192.168.1.1', '192.168.1.10',
            '/d', '/d/manifest.json', sleep=0.5, retries=5, backoff=2.0,
            reconnect_every=50, preview=False, ptp_verify=True, verbose=True)
        self.assertNotIn('--dry-run', argv)
        self.assertIn('--verify-ptp', argv)
        self.assertEqual(argv[argv.index('--ptp-bind') + 1], '192.168.1.10')
        self.assertIn('-v', argv)


class TestMapPullRc(unittest.TestCase):
    def test_map(self):
        self.assertEqual(rc.map_pull_rc(0)[1], 0)
        self.assertEqual(rc.map_pull_rc(1)[1], 1)
        self.assertEqual(rc.map_pull_rc(2)[1], 2)
        self.assertEqual(rc.map_pull_rc(3)[1], 3)
        self.assertEqual(rc.map_pull_rc(99)[1], 4)
        self.assertIn('resume', rc.map_pull_rc(2)[0].lower())


if __name__ == '__main__':
    unittest.main()
