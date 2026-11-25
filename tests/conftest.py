import sys, os

deps = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.deps"))
if os.path.exists(deps) and deps not in sys.path:
    sys.path.insert(0, deps)

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)
