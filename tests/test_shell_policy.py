"""Tests for the deterministic shell policy."""

from gptme_grimdall.shell_policy import evaluate_shell


def test_blocks_rm_rf_root():
    assert evaluate_shell("rm -rf /") is not None


def test_blocks_rm_rf_home():
    assert evaluate_shell("rm -rf ~") is not None


def test_blocks_rm_rf_absolute_path():
    assert evaluate_shell("rm -rf /tmp/data") is not None


def test_blocks_rm_force_system_file():
    assert evaluate_shell("rm -f /etc/passwd") is not None


def test_allows_relative_rm():
    # relative path within the workspace is not catastrophic
    assert evaluate_shell("rm -rf node_modules") is None


def test_blocks_drop_table():
    assert evaluate_shell("DROP TABLE users;") is not None


def test_blocks_delete_from():
    assert evaluate_shell("DELETE FROM users WHERE 1=1;") is not None


def test_blocks_mkfs():
    assert evaluate_shell("mkfs.ext4 /dev/sda1") is not None


def test_blocks_dd():
    assert evaluate_shell("dd if=/dev/zero of=/dev/sda") is not None


def test_blocks_fork_bomb():
    assert evaluate_shell(":(){ :|:& };:") is not None


def test_blocks_chmod_deny_all():
    assert evaluate_shell("chmod -R 000 /") is not None


def test_blocks_find_delete():
    assert evaluate_shell("find . -delete") is not None


def test_blocks_python_rmtree():
    assert evaluate_shell("shutil.rmtree('/')") is not None


def test_allows_benign_commands():
    assert evaluate_shell("ls -la") is None
    assert evaluate_shell("git status") is None
    assert evaluate_shell("cat README.md") is None
