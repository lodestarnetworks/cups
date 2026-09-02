# Contributing

The project is currently in a private hardening phase and is not yet accepting
external contributions. These rules define the intended public workflow.

- Keep SGW-C and SGW-U ownership boundaries explicit.
- Add tests for every protocol and state transition.
- Treat packet input, persisted state, and API parameters as untrusted.
- Do not log raw subscriber identifiers or payloads by default.
- Run `make verify` before proposing a change.
- Include a specification reference and an interoperability test for new wire
  behaviour.
- Keep generated files reproducible and document their source.

The public repository will adopt a Developer Certificate of Origin or a
contributor licence policy before accepting third-party patches.
