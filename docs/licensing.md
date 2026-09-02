# Licensing and clean-room policy

Lodestar CUPS is being developed as an original implementation. Public standards,
interoperability observations, and independently produced tests may inform its
behaviour, but source code from other Serving Gateway implementations must not
be copied into this repository unless its licence and provenance have first
been reviewed and recorded.

## Project licence

The project is distributed under the Apache License 2.0. It is permissive,
includes an express patent grant, and is familiar to telecom and cloud
infrastructure contributors. See `LICENSE` for the complete terms.

## Reference projects

VectorCore SGW may be studied for externally observable behaviour, documented
scope, deployment assumptions, and compatibility targets. New implementation
work should be based on 3GPP specifications and original designs. Any future
code-level reuse must be isolated, attributed, and checked against its exact
licence revision before inclusion.

## Dashboard design

The operator dashboard uses an original Lodestar CUPS identity and interface. Its
colour system, flat editorial layout, and typography are inspired by the visual
language requested from the Lodestar Networks website. It does not include the
Lodestar name, logo, copy, imagery, or downloaded site assets. Before a public
release, maintainers should perform a final trademark and visual-identity
review.

## Dependency review

Before the first public tag:

1. Generate a complete Go and JavaScript dependency inventory.
2. Record every direct dependency's licence and source.
3. Produce an SBOM for each release artifact.
4. Add automated licence and vulnerability checks to CI.
5. Preserve required notices in source and binary distributions.
