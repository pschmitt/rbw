"""Tests for the monorepo Home Assistant integration exporter/installer."""

from __future__ import annotations

import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).parents[2]
SCRIPT = REPO_ROOT / "tools" / "homeassistant-integration.sh"


class HomeAssistantPackageTests(unittest.TestCase):
    def test_export_is_deterministic_and_contains_only_component_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            first_archive = Path(temp_dir) / "first.tar"
            second_archive = Path(temp_dir) / "second.tar"
            first = subprocess.run(
                [str(SCRIPT), "export", str(first_archive)],
                cwd=REPO_ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [str(SCRIPT), "export", str(second_archive)],
                cwd=REPO_ROOT,
                check=True,
                capture_output=True,
                text=True,
            )

            self.assertEqual(first_archive.read_bytes(), second_archive.read_bytes())
            self.assertIn("sha256 ", first.stdout)
            with tarfile.open(first_archive) as archive:
                names = archive.getnames()

        self.assertTrue(names)
        self.assertTrue(
            all(
                name == "custom_components/rbw" or name.startswith("custom_components/rbw/")
                for name in names
            )
        )
        self.assertIn("custom_components/rbw/manifest.json", names)
        self.assertIn("custom_components/rbw/api.py", names)
        self.assertFalse(any(name.endswith((".pem", ".key", ".crt")) for name in names))
        self.assertFalse(any("__pycache__" in name or name.endswith(".pyc") for name in names))

    def test_export_refuses_to_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "existing.tar"
            archive.write_text("keep", encoding="utf-8")
            result = subprocess.run(
                [str(SCRIPT), "export", str(archive)],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
            )
            original = archive.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 1)
        self.assertEqual(original, "keep")
        self.assertIn("Refusing to overwrite", result.stderr)

    def test_install_uses_archive_and_ssh_without_connecting_in_test(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            test_root = Path(temp_dir)
            fake_bin = test_root / "bin"
            fake_bin.mkdir()
            archive_copy = test_root / "transferred.tar"
            scp_args = test_root / "scp-args"
            ssh_args = test_root / "ssh-args"
            remote_script = test_root / "remote-script"
            config_root = test_root / "ha-config"
            remote_tmp = test_root / "remote-tmp"
            (config_root / ".git/info").mkdir(parents=True)
            (config_root / ".git/info/exclude").write_text("", encoding="utf-8")
            remote_tmp.mkdir()

            fake_scp = fake_bin / "scp"
            fake_scp.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                'printf \'%s\\n\' "$@" > "$RBW_TEST_SCP_ARGS"\n'
                "archive=\n"
                "after_separator=\n"
                'for argument in "$@"\n'
                "do\n"
                '  if [[ -n "$after_separator" ]]\n'
                "  then\n"
                '    archive="$argument"\n'
                "    break\n"
                "  fi\n"
                '  if [[ "$argument" == -- ]]\n'
                "  then\n"
                "    after_separator=1\n"
                "  fi\n"
                "done\n"
                'cp -- "$archive" "$RBW_TEST_ARCHIVE_COPY"\n',
                encoding="utf-8",
            )
            fake_ssh = fake_bin / "ssh"
            fake_ssh.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                'printf \'%s\\n\' "$@" > "$RBW_TEST_SSH_ARGS"\n'
                'command="${!#}"\n'
                'archive_id="${command#sh -s }"\n'
                'cp -- "$RBW_TEST_ARCHIVE_COPY" "$RBW_TEST_REMOTE_TMP/rbw-ha-$archive_id.tar"\n'
                'cat > "$RBW_TEST_REMOTE_SCRIPT"\n'
                'sed -e "s|/config|$RBW_TEST_CONFIG_ROOT|g" '
                '-e "s|/tmp/rbw-ha|$RBW_TEST_REMOTE_TMP/rbw-ha|g" "$RBW_TEST_REMOTE_SCRIPT" '
                '> "$RBW_TEST_REMOTE_SCRIPT.transformed"\n'
                'sh -s "$archive_id" < "$RBW_TEST_REMOTE_SCRIPT.transformed"\n',
                encoding="utf-8",
            )
            fake_scp.chmod(0o755)
            fake_ssh.chmod(0o755)

            env = {
                **os.environ,
                "PATH": f"{fake_bin}:{os.environ['PATH']}",
                "RBW_TEST_SCP_ARGS": str(scp_args),
                "RBW_TEST_SSH_ARGS": str(ssh_args),
                "RBW_TEST_ARCHIVE_COPY": str(archive_copy),
                "RBW_TEST_REMOTE_SCRIPT": str(remote_script),
                "RBW_TEST_CONFIG_ROOT": str(config_root),
                "RBW_TEST_REMOTE_TMP": str(remote_tmp),
            }
            result = subprocess.run(
                [str(SCRIPT), "install", "--port", "22", "ha-shell"],
                cwd=REPO_ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )

            self.assertIn("-P\n22\n", scp_args.read_text(encoding="utf-8"))
            self.assertIn("-p\n22\n", ssh_args.read_text(encoding="utf-8"))
            self.assertIn("ha-shell", ssh_args.read_text(encoding="utf-8"))
            with tarfile.open(archive_copy) as archive:
                self.assertIn("custom_components/rbw/manifest.json", archive.getnames())
            script_text = remote_script.read_text(encoding="utf-8")
            self.assertIn("/config/custom_components-local", script_text)
            self.assertIn("/config/custom_components/rbw", script_text)
            self.assertIn("/config/.git/info/exclude", script_text)
            self.assertIn("ln -sfn", script_text)
            self.assertIn("Installed rbw integration version", script_text)
            self.assertIn("Installed rbw integration version", result.stdout)
            component_link = config_root / "custom_components/rbw"
            self.assertTrue(component_link.is_symlink())
            self.assertTrue((component_link / "manifest.json").is_file())
            self.assertIn(
                "/custom_components-local/rbw-integration-*",
                (config_root / ".git/info/exclude").read_text(encoding="utf-8"),
            )

    def test_install_rejects_option_like_target_before_network(self) -> None:
        result = subprocess.run(
            [str(SCRIPT), "install", "--option-like"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("valid SSH target", result.stderr)


if __name__ == "__main__":
    unittest.main()
