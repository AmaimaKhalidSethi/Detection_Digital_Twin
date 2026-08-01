# Starter Sigma rule library

Rules here are unmodified copies of real, public rules from the
[SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) repository (the community
Sigma rule collection), used as starter content and for the integration
test in `tests/test_integration_pipeline.py`.

- `proc_creation_win_powershell_base64_encoded_cmd.yml` — "Suspicious
  Encoded PowerShell Command Line" (T1059.001), authored by Florian Roth
  (Nextron Systems) et al., licensed under the Detection Rule License
  (DRL) 1.1 by SigmaHQ. See the upstream repository for license terms
  before redistributing.

Add more rules from SigmaHQ under `rules/windows/` and `rules/linux/` to
grow the ATT&CK coverage matrix (Section 14 of the SDD lists the curated
15-25 technique target).
