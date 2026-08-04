export const PLACEHOLDER_YAML = `title: My detection rule
status: test
description: What this rule detects
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
    condition: selection
level: medium
tags:
    - attack.execution
    - attack.t1059.001
`;
