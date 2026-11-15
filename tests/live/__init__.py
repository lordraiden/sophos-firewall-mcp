"""Live appliance verification package (opt-in, read-only).

Every test here is marked ``live`` and skipped unless ``SOPHOS_HOST``, ``SOPHOS_PORT`` and
``SOPHOS_API_KEY``/``SOPHOS_API_KEY_FILE`` are set. See ``conftest.py`` for the safety
invariants and ``docs/live-evidence/README.md`` for the recording protocol.
"""
