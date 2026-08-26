import json
import os
import sys

assert sys.argv[1] == "literal;not-shell"
assert os.environ["FIXTURE_MODE"] == "bounded"
assert "SECRET_SHOULD_NOT_LEAK" not in os.environ
assert "HOME" not in os.environ

print(json.dumps({
    "schema": "project.ops.status/v1",
    "project": "example-fixture",
    "generated_at": "2026-08-25T12:00:00Z",
    "manifest": {
        "schema": "project.concerns/v1",
        "path": ".ops/concerns.toml",
    },
    "producer": {"id": "example-fixture.status", "session_id": "fixture-session"},
    "authority": {"kind": "producer-local"},
    "concerns": [
        {
            "id": "example.queue.progress",
            "question": "example.question.queue-progress/v1",
            "profile": "example.profile.local/v1",
            "required": True,
            "description": "Did the fixture produce an observation about bounded queue progress?",
            "observation": {
                "observation_present": True,
                "local_state": "UNKNOWN",
                "domain_state": None,
                "observed_at": "2026-08-25T11:00:00Z",
                "valid_for_seconds": None,
                "reason": "the fixture explicitly cannot establish progress",
                "facts": {"depth": 4},
            },
        },
        {
            "id": "example.optional.mode",
            "question": "example.question.optional-mode/v1",
            "profile": "example.profile.local/v1",
            "required": False,
            "description": "What fixture-specific optional mode did the producer report?",
            "observation": {
                "observation_present": True,
                "local_state": "EXAMPLE_PAUSED",
                "domain_state": "FROBNICATED",
                "observed_at": None,
                "valid_for_seconds": None,
                "reason": "an intentionally unknown project-specific state",
                "facts": {"fixture": True},
            },
        },
    ],
}))
