#!/usr/bin/env bash
# Drives the RaxuisCLI demo recording. Tools: asciinema + agg (no ffmpeg needed).
#   brew install asciinema agg
# Regenerate the GIF with:
#   make build VERSION=v0.1.0
#   asciinema rec --overwrite --window-size 104x30 -c "bash docs/demo-script.sh" docs/demo.cast
#   agg --font-size 22 --theme dracula --line-height 1.35 --renderer resvg docs/demo.cast docs/demo.gif
set -u
export PATH="$PWD/bin:$PATH"

prompt='\033[38;5;213m➜\033[0m \033[38;5;45m~/RaxuisCLI\033[0m'

# Print the prompt, "type" the command char by char, then run it.
run() {
  printf "%b " "$prompt"
  local cmd="$1"
  for ((i = 0; i < ${#cmd}; i++)); do
    printf '%s' "${cmd:i:1}"
    sleep 0.02
  done
  printf '\n'
  sleep 0.4
  eval "$cmd"
  echo
  sleep "${2:-2}"
}

clear
sleep 0.8
run "raxuiscli version" 2
run 'raxuiscli cipher caesar "Attack at dawn" --shift 3' 2.5
run "raxuiscli demo web" 5
sleep 1
