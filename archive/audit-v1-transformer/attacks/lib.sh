# Shared shell helpers for the runtime-IDS data generators.
# This file is meant to be sourced, not executed.

# Sub-second UTC timestamp (macOS `date` has only 1-second resolution).
now() { python3 -c 'import datetime;print(datetime.datetime.now(datetime.timezone.utc).isoformat())'; }

# Random integer in [$1, $2].
ri() { echo $(( RANDOM % ($2 - $1 + 1) + $1 )); }

# Succeeds with probability $1 percent.
coin() { [ $(( RANDOM % 100 )) -lt "$1" ]; }

# Occasionally pause briefly, so per-user event rates vary between runs.
jitter() { [ $(( RANDOM % 100 )) -lt 25 ] && sleep "0.$(( RANDOM % 4 + 1 ))" || true; }

# Print the arguments in random order, one per line (Fisher-Yates shuffle).
shuffle() {
  local arr=("$@") i j tmp
  for (( i=${#arr[@]} - 1; i > 0; i-- )); do
    j=$(( RANDOM % (i + 1) ))
    tmp=${arr[i]}; arr[i]=${arr[j]}; arr[j]=$tmp
  done
  [ ${#arr[@]} -gt 0 ] && printf '%s\n' "${arr[@]}"
}
