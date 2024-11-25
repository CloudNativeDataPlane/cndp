#! /bin/bash -e
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2024 Red Hat, Inc.

set -euo pipefail

username=""
userid=""

usage() {
  cat <<EOF >&2
Usage: $0
   -u | --user <username>
   -g | --gid <userid>
EOF
  exit 1
}

# Parse command-line arguments
args=$(getopt -o u:g: --long user:,gid: -n "$0" -- "$@") || usage

eval set -- "$args"
while [ $# -gt 0 ]; do
  case "$1" in
    -h | --help)
      usage
      ;;
    -u | --user)
      username="$2"
      shift 2
      ;;
    -g | --gid)
      userid="$2"
      shift 2
      ;;
    --)
      shift
      break
      ;;
    *)
      echo "Unsupported option: $1" >&2
      usage
      ;;
  esac
done

# Validate required parameters
if [ -z "$username" ] || [ -z "$userid" ]; then
  echo "Error: --user and --gid are required." >&2
  usage
fi

USER_NAME="$username"
USER_UID="$userid"
USER_GID="$USER_UID"
HOME_DIR="/home/$USER_NAME"

# Exit if the user is root
if [ "$USER_NAME" = "root" ]; then
  exit 0
fi

if ! getent group "$USER_NAME" >/dev/null; then
  groupadd --gid "$USER_GID" "$USER_NAME"
fi

if ! getent passwd "$USER_NAME" >/dev/null; then
  useradd --uid "$USER_UID" --gid "$USER_GID" -m "$USER_NAME"
fi

# Ensure $HOME exists when starting
if [ ! -d "${HOME_DIR}" ]; then
  mkdir -p "${HOME_DIR}"
fi

# Add current (arbitrary) user to /etc/passwd and /etc/group
if [ -w /etc/passwd ]; then
  echo "${USER_NAME:-user}:x:$(id -u):0:${USER_NAME:-user}:${HOME_DIR}:/bin/bash" >> /etc/passwd
  echo "${USER_NAME:-user}:x:$(id -u):" >> /etc/group
fi

# Fix up permissions
chown "$USER_NAME:$USER_GID" -R "/home/$USER_NAME"
chown "$USER_NAME:$USER_GID" -R /opt
mkdir -p "/run/user/$USER_UID"
chown "$USER_NAME:$USER_GID" "/run/user/$USER_UID"
