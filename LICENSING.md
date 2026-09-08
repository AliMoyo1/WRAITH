# WRAITH Licensing

This document records the license decision for WRAITH's own code and the
compatibility analysis for the components it orchestrates. The per-component
matrix and obligations are in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md);
pinned versions are in [`config/engines.lock.yaml`](config/engines.lock.yaml).

## WRAITH's own license

> **Decision required.** This branch adds an Apache-2.0 [`LICENSE`](LICENSE) as a
> proposed default. It is not final until you confirm it. Change it before merge
> if you intend a different model.

Recommendation: **Apache-2.0**, because:

- The three primary engines (SkillSpector, Strix, CubeSandbox) are Apache-2.0,
  so a permissive, patent-grant license aligns with the ecosystem WRAITH sits in.
- It is the common choice for security tooling and is compatible with MIT
  (Ponytail) and with aggregating GPL tools as separate processes.
- It keeps the door open for both open collaboration and commercial use.

Alternatives to consider deliberately:

- **AGPL-3.0** if you want to require that hosted/SaaS forks publish changes.
  This is stronger copyleft and changes downstream obligations significantly.
- **Proprietary / source-available** if WRAITH is a commercial product. In that
  case remove the Apache `LICENSE` and replace it with your commercial terms.

## Compatibility posture

WRAITH is an **orchestrator**: each engine and tool runs as a separate process
behind a JSON contract. WRAITH does not statically link, embed, or modify them.
That aggregation model is what keeps GPL and commercial tools usable without
imposing their terms on WRAITH's own code.

Hard rules for any downloadable release:

1. Do not bundle SQLMap (GPL-2.0) inside a WRAITH artifact without legal review.
2. Do not redistribute Nmap inside a proprietary product; the NPSL requires an
   OEM license for that. Have the operator install Nmap themselves.
3. Never redistribute Burp Suite or Shodan; they are commercial and user-licensed.
4. Ship signed release artifacts with checksums and provenance. No
   curl-to-shell install path.

## SBOM

A CycloneDX SBOM is generated at [`sbom/wraith.sbom.json`](sbom/wraith.sbom.json).
Regenerate it whenever `config/engines.lock.yaml` or the Python dependencies
change, and attach it to each release.

This document is engineering guidance, not legal advice. Confirm the license
choice and all redistribution decisions with counsel before publishing.
