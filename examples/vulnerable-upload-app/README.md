# Vulnerable Upload Demo App

This tiny app exists only for the RepoGuard demo.

It intentionally contains unsafe patterns:

- accepts multiple uploaded files
- has no max file count
- has no max file size
- has no file type allowlist
- writes uploaded bytes directly into an in-memory database list
- contains a fake API key-shaped value for scanner demonstration

Do not use it as a real application.

