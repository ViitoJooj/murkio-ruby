# Shared spec (copy)

The contract every Murkio SDK is tested against: token vectors, canvas fixtures, the
default canvas, the built-in texts and the error translations.

This directory is a **copy**. The files are kept in the Murkio identity service
(`libs/spec`) and synced from there, so every SDK runs exactly the same cases. Do not edit
them here: `infra/pipeline/verify_spec.py` fails when a file differs from `CHECKSUMS`.
