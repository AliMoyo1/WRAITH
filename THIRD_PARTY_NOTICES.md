# Third-Party Notices

WRAITH orchestrates external engines and tools. It does **not** bundle or
redistribute any of them: the operator installs or clones each one locally, and
WRAITH invokes it as a separate process. This file records the components WRAITH
is designed to work with, their licenses, and any redistribution constraints.

Pinned versions are in [`config/engines.lock.yaml`](config/engines.lock.yaml).

## Engines (cloned into ./repos by the operator)

| Component | Source | License | Redistributed by WRAITH |
|-----------|--------|---------|-------------------------|
| SkillSpector | NVIDIA/SkillSpector | Apache-2.0 | No (cloned source) |
| Strix | usestrix/strix | Apache-2.0 | No (cloned source) |
| CubeSandbox | TencentCloud/CubeSandbox | Apache-2.0 | No (service; x86_64 Linux + KVM) |
| Ponytail | DietrichGebert/ponytail | MIT | No (node plugin) |

## External tools (invoked from the host, never bundled)

| Tool | Source | License | Notes |
|------|--------|---------|-------|
| Metasploit Framework | rapid7/metasploit-framework | BSD-3-Clause | Gated behind engagement authorization |
| SQLMap | sqlmapproject/sqlmap | GPL-2.0 | Redistribution needs per-artifact legal review, not a blanket exclusion |
| Burp Suite | PortSwigger | Commercial | User-licensed; never redistributed |
| Nmap | nmap.org | NPSL | The Nmap Public Source License restricts redistribution inside proprietary products; commercial redistribution requires an OEM license (https://nmap.org/npsl/) |
| Shodan | shodan.io | Commercial API / ToS | Remote service under its own terms |

## Runtime dependency

| Package | License | Use |
|---------|---------|-----|
| PyYAML | MIT | Config parsing in the CLI layer |

## Not a WRAITH component

- **Handy** (cjpais/Handy, MIT) is unrelated speech-to-text software. It is not
  used by WRAITH and appears only in older exploratory notes. Voice
  transcription must never serve as authorization or identity evidence.

## Obligations summary

- Apache-2.0 and MIT components: retain their copyright and license notices when
  their source is present in `./repos/`. WRAITH does not modify or redistribute
  them, so no combined-work obligation is triggered by orchestration alone.
- GPL-2.0 (SQLMap): invoking it as a separate, unmodified process is generally
  aggregation, not a derivative work. Do not statically link or embed it, and
  seek legal review before shipping it inside any WRAITH release artifact.
- NPSL (Nmap) and commercial tools (Burp, Shodan): never include in a WRAITH
  distribution; require the operator to install them under their own terms.

Confirm all of the above with counsel before publishing any downloadable
WRAITH release. This file is engineering guidance, not legal advice.
