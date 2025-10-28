import unittest
from unittest.mock import patch
import tempfile
from pathlib import Path
from wg_installer.main import detect_wan_iface_and_ip, first_host_and_client, build_client_bundle
import ipaddress
from pathlib import Path

class TestMain(unittest.TestCase):

    @patch('subprocess.check_output')
    def test_detect_wan_iface_and_ip(self, mock_check_output):
        # Mock the output of the 'ip route' and 'ip addr' commands
        mock_check_output.side_effect = [
            b'default via 192.168.1.1 dev eth0',
            b'2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n    inet 192.168.1.100/24 brd 192.168.1.255 scope global dynamic noprefixroute eth0'
        ]

        iface, cidr = detect_wan_iface_and_ip()
        self.assertEqual(iface, 'eth0')
        self.assertEqual(cidr, '192.168.1.100/24')

    def test_first_host_and_client(self):
        server_ip, client_ip, prefix = first_host_and_client('10.0.0.0/24')
        self.assertEqual(server_ip, ipaddress.IPv4Address('10.0.0.1'))
        self.assertEqual(client_ip, ipaddress.IPv4Address('10.0.0.2'))
        self.assertEqual(prefix, 24)

    def test_build_client_bundle_dry_run(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Override the EXPORT_ROOT to use the temporary directory
            with patch('wg_installer.main.EXPORT_ROOT', Path(tmpdir)):
                zip_path = build_client_bundle(
                    public_host='1.2.3.4',
                    pub_port=12345,
                    wg_port=54321,
                    wg_subnet='10.0.0.0/24',
                    masking='STUN',
                    dry=True
                )

                # Check that the zip file was not created
                self.assertFalse(zip_path.exists())

    @patch('wg_installer.main.detect_wan_iface_and_ip')
    @patch('wg_installer.main.ask')
    @patch('wg_installer.main.ensure_packages')
    @patch('wg_installer.main.ensure_keys')
    @patch('wg_installer.main.create_wg_conf')
    @patch('wg_installer.main.ensure_obfuscator_built')
    @patch('wg_installer.main.ensure_obfuscator_conf')
    @patch('wg_installer.main.nft_apply_snippet')
    @patch('wg_installer.main.enable_services')
    @patch('wg_installer.main.build_client_bundle')
    def test_main_dry_run(self, mock_build_client_bundle, mock_enable_services, mock_nft_apply_snippet, mock_ensure_obfuscator_conf, mock_ensure_obfuscator_built, mock_create_wg_conf, mock_ensure_keys, mock_ensure_packages, mock_ask, mock_detect_wan_iface_and_ip):
        # Mock the return values of the patched functions
        mock_detect_wan_iface_and_ip.return_value = ('eth0', '192.168.1.100/24')
        mock_ask.side_effect = ['12345', '54321', '10.0.0.0/24', 'STUN', '1.2.3.4']
        mock_build_client_bundle.return_value = Path('/tmp/wg-client-1.2.3.4-12345.zip')

        # Redirect stdout to capture the output
        from io import StringIO
        import sys
        old_stdout = sys.stdout
        sys.stdout = captured_output = StringIO()

        # Call the main function with the --dry-run argument
        with patch.object(sys, 'argv', ['wg_installer.py', '--dry-run']):
            from wg_installer.main import main
            main()

        # Restore stdout
        sys.stdout = old_stdout

        # Check that the output contains the expected summary
        output = captured_output.getvalue()
        self.assertIn('=== SUMMARY ===', output)
        self.assertIn('Interface: wg0', output)
        self.assertIn('Config: /etc/wireguard/wg0.conf', output)
        self.assertIn('Subnet: 10.0.0.0/24', output)
        self.assertIn('Listen: 127.0.0.1:54321', output)
        self.assertIn('Binary: /usr/local/bin/wg-obfuscator', output)
        self.assertIn('Config: /etc/wg-obfuscator.conf', output)
        self.assertIn('Public: 0.0.0.0:12345', output)
        self.assertIn('Masking: STUN', output)
        self.assertIn('Snippet: /etc/nftables.d/50-wg-installer.nft', output)
        self.assertIn('NAT: Masquerade 10.0.0.0/24 -> eth0', output)
        self.assertIn('ZIP: /tmp/wg-client-1.2.3.4-12345.zip', output)

if __name__ == '__main__':
    unittest.main()

