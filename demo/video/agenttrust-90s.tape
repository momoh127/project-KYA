# AgentTrust 90-second demo (terminal recording)
# Render:  pnpm dev:api   (in another terminal)  then  vhs demo/video/agenttrust-90s.tape
# Output:  demo/video/out/agenttrust-90s.{mp4,gif}   (git-ignored; attach to emails / upload)
Output demo/video/out/agenttrust-90s.mp4
Output demo/video/out/agenttrust-90s.gif

Set Shell "bash"
Set FontSize 20
Set Width 1600
Set Height 900
Set Padding 28
Set Theme "Dracula"
Set TypingSpeed 35ms
Set CursorBlink false

Hide
Type "export AGENTTRUST_BASE_URL=${AGENTTRUST_BASE_URL:-http://localhost:4000} PACE=2600; clear"
Enter
Sleep 300ms
Show

Type "pnpm --silent --filter @agenttrust/demo-procurement-agent video"
Sleep 600ms
Enter
# 25 pacing beats x 2.6 s ≈ 65 s, plus API calls and typing ≈ 72 s; hold the closing frame.
Sleep 78s
