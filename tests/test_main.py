import unittest
from unittest.mock import patch, MagicMock
import tempfile
from pathlib import Path
import ipaddress
from pydantic import ValidationError
from wg_installer.core.config import Config
from wg_installer.core.runner import Runner
from wg_installer.net.detect import detect_wan_iface_and_cidr
from wg_installer.export.bundle import build_client_bundle
from wg_installer.android.builder import AndroidAPKBuilder, AndroidBuildConfig
from wg_installer.core.state import StateDB

class TestCore(unittest.TestCase):

    def test_config_validation(self):
        # Valid config
        config = Config(
            public_host="1.2.3.4",
            pub_port=12345,
            wg_port=54321,
            wg_subnet="10.0.0.0/24",
            masking="STUN",
            mtu=1420
        )
        self.assertEqual(config.public_host, "1.2.3.4")

        # Invalid subnet
        with self.assertRaises(ValidationError):
            Config(
                public_host="1.2.3.4",
                pub_port=12345,
                wg_port=54321,
                wg_subnet="invalid",
                masking="STUN"
            )

        # Subnet too small
        with self.assertRaises(ValidationError):
            Config(
                public_host="1.2.3.4",
                pub_port=12345,
                wg_port=54321,
                wg_subnet="10.0.0.0/32",
                masking="STUN"
            )

    def test_runner_dry_run(self):
        runner = Runner(dry_run=True)
        result = runner.run(["echo", "test"])
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")

    def test_detect_wan_iface_and_cidr(self):
        runner = Runner()
        with patch.object(runner, 'run') as mock_run:
            mock_run.side_effect = [
                MagicMock(stdout='default via 192.168.1.1 dev eth0\n'),
                MagicMock(stdout='2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n    inet 192.168.1.100/24 brd 192.168.1.255 scope global dynamic noprefixroute eth0\n')
            ]
            iface, cidr = detect_wan_iface_and_cidr(runner)
            self.assertEqual(iface, 'eth0')
            self.assertEqual(cidr, '192.168.1.100/24')

    def test_build_client_bundle_dry_run(self):
        runner = Runner(dry_run=True)
        with patch('wg_installer.export.bundle.EXPORT_ROOT', Path(tempfile.mkdtemp())):
            zip_path = build_client_bundle(
                public_host='1.2.3.4',
                pub_port=12345,
                wg_port=54321,
                client_ip='10.0.0.2',
                prefix=24,
                masking='STUN',
                obf_key='testkey',
                r=runner
            )
            self.assertFalse(zip_path.exists())

    def test_android_builder_dry_run(self):
        runner = Runner(dry_run=True)
        config = AndroidBuildConfig(build_dir=Path(tempfile.mkdtemp()))
        state_db = StateDB(Path(tempfile.mktemp()))
        builder = AndroidAPKBuilder(config, runner, state_db)
        server_config = Config(
            public_host="1.2.3.4",
            pub_port=12345,
            wg_port=54321,
            wg_subnet="10.7.0.0/24",
            masking="STUN",
            mtu=1420
        )
        # In dry-run, it should not actually build, but we can check it doesn't raise
        with patch.object(builder.runner, 'run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            try:
                apk_path = builder.build_apk(server_config)
                # Since dry-run, apk_path might not exist, but method should complete
                self.assertIsInstance(apk_path, Path)
            except Exception as e:
                self.fail(f"build_apk raised an exception in dry-run: {e}")

if __name__ == '__main__':
    unittest.main()

