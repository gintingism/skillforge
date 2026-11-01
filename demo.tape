# VHS Tape Script for SkillForge Terminal Demo
# To generate the GIF: install VHS (https://github.com/charmbracelet/vhs) and run:
#   vhs demo.tape

Output assets/demo.gif

Set FontSize 15
Set Width 920
Set Height 540
Set Padding 20
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful

# 1. Inspect installed skills across all assistants
Type "uvx agent-skillforge doctor"
Sleep 500ms
Enter
Sleep 3s

# 2. Audit a specific skill for security issues & token costs
Type "uvx agent-skillforge audit ./skills/supply-chain-sentinel"
Sleep 500ms
Enter
Sleep 3s

# 3. Profile context token window consumption
Type "uvx agent-skillforge budget --builtin"
Sleep 500ms
Enter
Sleep 4s

# 4. Generate an official verified badge
Type "uvx agent-skillforge badge ./skills/supply-chain-sentinel"
Sleep 500ms
Enter
Sleep 4s
