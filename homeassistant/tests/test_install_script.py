"""Tests for the monorepo Home Assistant integration exporter/installer."""

from __future__ import annotations

import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).parents[2]
SCRIPT = REPO_ROOT / "tools" / "homeassistant-integration.sh"


def run_fake_install(
    *,
    corrupt_archive: bool = False,
    symlink_exclude: bool = False,
    symlink_git_root: bool = False,
    symlink_git_info: bool = False,
    symlink_local_root: bool = False,
    symlink_components_root: bool = False,
    symlink_versioned_root: bool = False,
    symlink_versioned_components: bool = False,
    symlink_versioned_package: bool = False,
    preexisting_stage: bool = False,
    malformed_stage_argument: bool = False,
) -> dict[str, object]:
    """Exercise SSH deployment locally with temporary remote paths."""
    with tempfile.TemporaryDirectory() as temp_dir:
        test_root = Path(temp_dir)
        fake_bin = test_root / "bin"
        fake_bin.mkdir()
        scp_args = test_root / "scp-args"
        scp_stage_mode = test_root / "scp-stage-mode"
        ssh_calls = test_root / "ssh-calls"
        remote_script = test_root / "remote-script"
        config_root = test_root / "ha-config"
        config_root.mkdir()
        git_root = config_root / ".git"
        git_info = git_root / "info"
        exclude_file = config_root / ".git/info/exclude"
        external_file = test_root / "external-exclude-target"
        external_git_root = test_root / "external-git-root"
        external_git_info = test_root / "external-git-info"
        external_file.write_text("keep this file\n", encoding="utf-8")
        external_git_root.mkdir()
        external_git_info.mkdir()
        external_install_root = test_root / "external-install-root"
        external_install_root.mkdir()
        if symlink_git_root:
            (external_git_root / "info").mkdir()
            (external_git_root / "info/exclude").write_text("keep git root\n", encoding="utf-8")
            git_root.symlink_to(external_git_root, target_is_directory=True)
        elif symlink_git_info:
            git_root.mkdir()
            (external_git_info / "exclude").write_text("keep git info\n", encoding="utf-8")
            git_info.symlink_to(external_git_info, target_is_directory=True)
        else:
            git_info.mkdir(parents=True)
        if symlink_exclude and not (symlink_git_root or symlink_git_info):
            exclude_file.symlink_to(external_file)
        elif not (symlink_git_root or symlink_git_info):
            exclude_file.write_text("", encoding="utf-8")
        if symlink_local_root:
            (config_root / "custom_components-local").symlink_to(
                external_install_root, target_is_directory=True
            )
        if symlink_components_root:
            (config_root / "custom_components").symlink_to(
                external_install_root, target_is_directory=True
            )
        remote_stage = Path(f"/tmp/rbw-ha.test{uuid.uuid4().hex}")
        extraction_stage_file = test_root / "extraction-stage-path"

        fake_scp = fake_bin / "scp"
        fake_scp.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            'printf \'%s\\n\' "$@" > "$RBW_TEST_SCP_ARGS"\n'
            "archive=\n"
            "destination=\n"
            "after_separator=\n"
            'for argument in "$@"\n'
            "do\n"
            '  if [[ "$argument" == -- ]]\n'
            "  then\n"
            "    after_separator=1\n"
            '  elif [[ -n "$after_separator" && -z "$archive" ]]\n'
            "  then\n"
            '    archive="$argument"\n'
            '  elif [[ -n "$after_separator" ]]\n'
            "  then\n"
            '    destination="$argument"\n'
            "  fi\n"
            "done\n"
            '[[ "$destination" == *:"$RBW_TEST_REMOTE_STAGE/archive.tar" ]]\n'
            'stat -c \'%a\' "$RBW_TEST_REMOTE_STAGE" > "$RBW_TEST_SCP_STAGE_MODE"\n'
            'cp -- "$archive" "$RBW_TEST_REMOTE_STAGE/archive.tar"\n'
            'if [[ -n "${RBW_TEST_CORRUPT_ARCHIVE:-}" ]]\n'
            "then\n"
            '  printf tampered >> "$RBW_TEST_REMOTE_STAGE/archive.tar"\n'
            "fi\n",
            encoding="utf-8",
        )
        fake_ssh = fake_bin / "ssh"
        fake_ssh.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            'printf \'%s\\n\' "$@" >> "$RBW_TEST_SSH_CALLS"\n'
            'command="${!#}"\n'
            "if [[ \"$command\" == 'umask 077; mktemp -d /tmp/rbw-ha.XXXXXXXXXX' ]]\n"
            "then\n"
            '  mkdir -m 0700 "$RBW_TEST_REMOTE_STAGE"\n'
            "  printf '%s\\n' \"$RBW_TEST_REMOTE_STAGE\"\n"
            "  exit 0\n"
            "fi\n"
            'if [[ "$command" == "rm -rf \'$RBW_TEST_REMOTE_STAGE\'" ]]\n'
            "then\n"
            '  rm -rf "$RBW_TEST_REMOTE_STAGE"\n'
            "  exit 0\n"
            "fi\n"
            'read -r shell dash_s archive_id remote_stage <<< "$command"\n'
            "[[ \"$shell $dash_s\" == 'sh -s' ]]\n"
            '[[ "$remote_stage" == "$RBW_TEST_REMOTE_STAGE" ]]\n'
            'versioned="$RBW_TEST_CONFIG_ROOT/custom_components-local/rbw-integration-$archive_id"\n'
            'if [[ -n "${RBW_TEST_SYMLINK_VERSIONED_ROOT:-}" ]]\n'
            "then\n"
            '  mkdir -p "$(dirname "$versioned")"\n'
            '  ln -s "$RBW_TEST_EXTERNAL_INSTALL_ROOT" "$versioned"\n'
            'elif [[ -n "${RBW_TEST_SYMLINK_VERSIONED_COMPONENTS:-}" ]]\n'
            "then\n"
            '  mkdir -p "$versioned"\n'
            '  ln -s "$RBW_TEST_EXTERNAL_INSTALL_ROOT" "$versioned/custom_components"\n'
            'elif [[ -n "${RBW_TEST_SYMLINK_VERSIONED_PACKAGE:-}" ]]\n'
            "then\n"
            '  mkdir -p "$versioned/custom_components"\n'
            '  ln -s "$RBW_TEST_EXTERNAL_INSTALL_ROOT" "$versioned/custom_components/rbw"\n'
            "fi\n"
            'if [[ -n "${RBW_TEST_MALFORMED_STAGE_ARGUMENT:-}" ]]\n'
            "then\n"
            "  remote_stage=/tmp/rbw-hax.invalid\n"
            "fi\n"
            'cat > "$RBW_TEST_REMOTE_SCRIPT"\n'
            'sed "s|/config|$RBW_TEST_CONFIG_ROOT|g" "$RBW_TEST_REMOTE_SCRIPT" '
            '> "$RBW_TEST_REMOTE_SCRIPT.transformed"\n'
            'if [[ -n "${RBW_TEST_PREEXISTING_STAGE:-}" ]]\n'
            "then\n"
            '  stage="$RBW_TEST_CONFIG_ROOT/custom_components-local/.rbw-stage-$archive_id-$$"\n'
            '  mkdir -p "$(dirname "$stage")"\n'
            '  mkdir "$stage"\n'
            '  printf preserve > "$stage/sentinel"\n'
            '  printf "%s" "$stage" > "$RBW_TEST_EXTRACTION_STAGE_FILE"\n'
            "fi\n"
            'exec sh -s "$archive_id" "$remote_stage" '
            '< "$RBW_TEST_REMOTE_SCRIPT.transformed"\n',
            encoding="utf-8",
        )
        fake_scp.chmod(0o755)
        fake_ssh.chmod(0o755)

        env = {
            **os.environ,
            "PATH": f"{fake_bin}:{os.environ['PATH']}",
            "RBW_TEST_SCP_ARGS": str(scp_args),
            "RBW_TEST_SCP_STAGE_MODE": str(scp_stage_mode),
            "RBW_TEST_SSH_CALLS": str(ssh_calls),
            "RBW_TEST_REMOTE_SCRIPT": str(remote_script),
            "RBW_TEST_CONFIG_ROOT": str(config_root),
            "RBW_TEST_REMOTE_STAGE": str(remote_stage),
            "RBW_TEST_EXTERNAL_INSTALL_ROOT": str(external_install_root),
            "RBW_TEST_EXTRACTION_STAGE_FILE": str(extraction_stage_file),
        }
        if corrupt_archive:
            env["RBW_TEST_CORRUPT_ARCHIVE"] = "1"
        if preexisting_stage:
            env["RBW_TEST_PREEXISTING_STAGE"] = "1"
        if malformed_stage_argument:
            env["RBW_TEST_MALFORMED_STAGE_ARGUMENT"] = "1"
        if symlink_versioned_root:
            env["RBW_TEST_SYMLINK_VERSIONED_ROOT"] = "1"
        if symlink_versioned_components:
            env["RBW_TEST_SYMLINK_VERSIONED_COMPONENTS"] = "1"
        if symlink_versioned_package:
            env["RBW_TEST_SYMLINK_VERSIONED_PACKAGE"] = "1"

        result = subprocess.run(
            [str(SCRIPT), "install", "--port", "22", "ha-shell"],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
        )
        component_link = config_root / "custom_components/rbw"
        exclude_contents = None
        if not exclude_file.is_symlink():
            exclude_contents = exclude_file.read_text(encoding="utf-8")
        extraction_stage = (
            Path(extraction_stage_file.read_text(encoding="utf-8"))
            if extraction_stage_file.exists()
            else None
        )
        outcome = {
            "result": result,
            "symlink_exists": component_link.is_symlink(),
            "component_exists": (component_link / "manifest.json").is_file(),
            "exclude_is_symlink": exclude_file.is_symlink(),
            "exclude_contents": exclude_contents,
            "external_contents": external_file.read_text(encoding="utf-8"),
            "external_git_root_contents": (
                (external_git_root / "info/exclude").read_text(encoding="utf-8")
                if (external_git_root / "info/exclude").exists()
                else None
            ),
            "external_git_info_contents": (
                (external_git_info / "exclude").read_text(encoding="utf-8")
                if (external_git_info / "exclude").exists()
                else None
            ),
            "stage_exists": remote_stage.exists(),
            "stage_mode": scp_stage_mode.read_text(encoding="utf-8").strip(),
            "extraction_stage": extraction_stage,
            "extraction_stage_exists": (extraction_stage is not None and extraction_stage.is_dir()),
            "extraction_sentinel": (
                (extraction_stage / "sentinel").read_text(encoding="utf-8")
                if extraction_stage is not None and (extraction_stage / "sentinel").exists()
                else None
            ),
            "local_root_is_symlink": (config_root / "custom_components-local").is_symlink(),
            "components_root_is_symlink": (config_root / "custom_components").is_symlink(),
            "external_install_contents": list(external_install_root.iterdir()),
            "commands": ssh_calls.read_text(encoding="utf-8"),
            "scp_arguments": scp_args.read_text(encoding="utf-8"),
            "remote_script": remote_script.read_text(encoding="utf-8"),
        }
        shutil.rmtree(remote_stage, ignore_errors=True)

    return outcome


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

    def test_install_uses_private_remote_staging_and_symlink_layout(self) -> None:
        outcome = run_fake_install()
        result = outcome["result"]
        self.assertEqual(result.returncode, 0)
        self.assertEqual(outcome["stage_mode"], "700")
        self.assertFalse(outcome["stage_exists"])
        self.assertIn("mktemp -d /tmp/rbw-ha.XXXXXXXXXX", outcome["commands"])
        self.assertIn("/tmp/rbw-ha.test", outcome["scp_arguments"])
        self.assertTrue(outcome["symlink_exists"])
        self.assertTrue(outcome["component_exists"])
        self.assertIn("/custom_components-local/rbw-integration-*", outcome["exclude_contents"])
        self.assertIn("sha256sum", outcome["remote_script"])
        self.assertIn('rm -rf "$remote_stage"', outcome["remote_script"])

    def test_install_rejects_symlinked_git_exclude(self) -> None:
        outcome = run_fake_install(symlink_exclude=True)
        result = outcome["result"]
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("non-regular Git exclude file", result.stderr)
        self.assertTrue(outcome["exclude_is_symlink"])
        self.assertEqual(outcome["external_contents"], "keep this file\n")
        self.assertFalse(outcome["symlink_exists"])
        self.assertFalse(outcome["stage_exists"])

    def test_install_rejects_symlinked_git_metadata_parents(self) -> None:
        expected = {
            "symlink_git_root": "keep git root\n",
            "symlink_git_info": "keep git info\n",
        }
        for option, original in expected.items():
            with self.subTest(option=option):
                outcome = run_fake_install(**{option: True})
                result = outcome["result"]
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Git metadata path", result.stderr)
                self.assertFalse(outcome["symlink_exists"])
                self.assertFalse(outcome["stage_exists"])
                if option == "symlink_git_root":
                    self.assertEqual(outcome["external_git_root_contents"], original)
                else:
                    self.assertEqual(outcome["external_git_info_contents"], original)

    def test_install_rejects_modified_archive_before_extraction(self) -> None:
        outcome = run_fake_install(corrupt_archive=True)
        result = outcome["result"]
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum did not match", result.stderr)
        self.assertFalse(outcome["symlink_exists"])
        self.assertFalse(outcome["component_exists"])
        self.assertFalse(outcome["stage_exists"])

    def test_install_cleanup_does_not_remove_preexisting_stage_path(self) -> None:
        outcome = run_fake_install(preexisting_stage=True)
        result = outcome["result"]
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(outcome["extraction_stage_exists"])
        self.assertEqual(outcome["extraction_sentinel"], "preserve")
        self.assertFalse(outcome["stage_exists"])

    def test_install_rejects_symlinked_component_roots(self) -> None:
        for option in ("symlink_local_root", "symlink_components_root"):
            with self.subTest(option=option):
                outcome = run_fake_install(**{option: True})
                result = outcome["result"]
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("symlink or non-directory install root", result.stderr)
                self.assertFalse(outcome["symlink_exists"])
                self.assertEqual(outcome["external_install_contents"], [])
                self.assertFalse(outcome["stage_exists"])

    def test_install_rejects_symlinked_version_path_components(self) -> None:
        options = (
            "symlink_versioned_root",
            "symlink_versioned_components",
            "symlink_versioned_package",
        )
        for option in options:
            with self.subTest(option=option):
                outcome = run_fake_install(**{option: True})
                result = outcome["result"]
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("symlink or non-directory version path", result.stderr)
                self.assertFalse(outcome["symlink_exists"])
                self.assertEqual(outcome["external_install_contents"], [])
                self.assertFalse(outcome["stage_exists"])

    def test_remote_script_rejects_stage_path_without_expected_prefix(self) -> None:
        outcome = run_fake_install(malformed_stage_argument=True)
        result = outcome["result"]
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid private staging directory", result.stderr)
        self.assertFalse(outcome["symlink_exists"])
        self.assertFalse(outcome["stage_exists"])

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
