import os

# The demo repo the tests' fake PRs come from. Production has no default (airlock/web/app.py GUEST_REPOS),
# so it is set here, before airlock.web.app reads it at import.
os.environ.setdefault("AIRLOCK_GUEST_REPOS", "Darkflib/airlock-demo")
