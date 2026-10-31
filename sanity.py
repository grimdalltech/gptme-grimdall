#!/usr/bin/env python3
"""Compact sanity check for gptme-grimdall (color-coded, verbose)."""
import os, sys, json
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
R="\033[31m"; G="\033[32m"; Y="\033[33m"; C="\033[36m"; B="\033[1m"; X="\033[0m"
def chk(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  {detail}" if detail else ""))
    return bool(cond)
from gptme_grimdall import __version__
from gptme_grimdall.shell_policy import evaluate_shell
from gptme_grimdall.secret_denial import is_secret_path
from gptme_grimdall.egress_allowlist import check_egress
ok = True
print(f"{B}{C}=== gptme-grimdall sanity ==={X}")
ok &= chk("version", __version__ == "0.1.0", __version__)
ok &= chk("benign shell allowed", evaluate_shell("ls -la") is None)
ok &= chk("rm -rf / blocked", evaluate_shell("rm -rf /") is not None)
ok &= chk("secret path blocked", is_secret_path("~/.ssh/id_rsa"))
ok &= chk("README allowed", not is_secret_path("README.md"))
ok &= chk("uppercase secret blocked", is_secret_path("~/.SSH/ID_RSA"))
ok &= chk("egress deny-all", check_egress("curl https://x.example", []) is not None)
# boundary: purposely fail, catch, fix
caught = False
try:
    assert is_secret_path("README.md") is True
except AssertionError:
    caught = True
    print(f"  {Y}CAUGHT{X} deliberate boundary failure")
ok &= chk("boundary caught", caught)
ok &= chk("boundary fixed", is_secret_path("README.md") is False)
print(f"{B}{'ALL PASS' if ok else 'FAILURES'}{X}")
sys.exit(0 if ok else 1)
