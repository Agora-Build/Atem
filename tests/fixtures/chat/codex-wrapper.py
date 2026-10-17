#!/usr/bin/python3 -I
# npm's `codex` stand-in: runs fake-codex.py (next to it) as its child, the
# way node runs the real Codex binary, and exits with its status.
import os, subprocess, sys

here = os.path.dirname(os.path.abspath(__file__))
sys.exit(subprocess.call([os.path.join(here, "fake-codex.py")] + sys.argv[1:]))
