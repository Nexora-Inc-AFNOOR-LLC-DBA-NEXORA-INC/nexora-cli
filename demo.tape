Output demo.gif
Set FontSize 13
Set Width 1400
Set Height 700
Set Theme "Dracula"
Set Padding 20

Type "# nexora-cli - The only NHI scanner that audits lifecycle, not just config"
Enter
Sleep 1s

Type "# 1. Static Analysis (like other scanners)"
Enter
Type "nexora scan workflows --path ./fixtures/vulnerable"
Enter
Sleep 3s

Type "# 2. Credential Lifecycle Audit (UNIQUE - no other scanner does this)"
Enter
Type "./scripts/demo-audit.sh"
Enter
Sleep 4s

Type "# 3. Identity Relationship Mapping (UNIQUE - blast radius analysis)"
Enter
Type "./scripts/demo-map.sh"
Enter
Sleep 4s
