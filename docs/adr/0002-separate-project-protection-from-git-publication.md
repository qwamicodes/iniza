# Separate Project protection from Git publication

Every selected Project is protected locally through a Project Capsule regardless of Git remote availability, while remote publication uses a separate immutable Push Plan and approval boundary. A Git remote cannot preserve dirty, ignored, stashed, detached, or deliberately unpublished state, and a failed or skipped push must never prevent local recovery evidence.
