#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

usage() {
  cat <<'USAGE'
Usage: Tools~/release.sh [pack|release|upload]

Commands:
  pack     Build dist/<package-name>-<version>.tgz with npm pack.
  release  Build the archive, then create or update the matching GitHub release.
  upload   Build the archive, then upload it to an existing GitHub release.

Environment:
  TAG       Release tag. Defaults to v<package.json version>.
  GH_REPO   Optional GitHub repository in owner/name form.
  DIST_DIR  Output directory. Defaults to dist.
USAGE
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command not found: $1" >&2
    exit 1
  fi
}

package_field() {
  node -p "require('./package.json').$1"
}

pack_archive() {
  require_command npm
  require_command node

  local dist_dir="${DIST_DIR:-dist}"
  mkdir -p "$dist_dir"

  local archive_name
  archive_name="$(npm pack --pack-destination "$dist_dir" | tail -n 1)"

  local archive_path="$dist_dir/$archive_name"
  if [[ ! -f "$archive_path" ]]; then
    echo "error: npm pack did not create $archive_path" >&2
    exit 1
  fi

  echo "$archive_path"
}

gh_repo_args() {
  if [[ -n "${GH_REPO:-}" ]]; then
    printf '%s\n' --repo "$GH_REPO"
  fi
}

command_name="${1:-pack}"
case "$command_name" in
  -h|--help|help)
    usage
    ;;
  pack)
    archive_path="$(pack_archive)"
    echo "created $archive_path"
    ;;
  release|upload)
    require_command gh
    archive_path="$(pack_archive)"

    package_name="$(package_field name)"
    package_version="$(package_field version)"
    tag="${TAG:-v$package_version}"
    repo_args=()
    while IFS= read -r arg; do
      repo_args+=("$arg")
    done < <(gh_repo_args)

    if [[ "$command_name" == "release" ]]; then
      if gh release view "$tag" "${repo_args[@]}" >/dev/null 2>&1; then
        gh release upload "$tag" "$archive_path" --clobber "${repo_args[@]}"
      else
        gh release create "$tag" "$archive_path" \
          --title "$package_name $package_version" \
          --notes "Release $package_name $package_version." \
          "${repo_args[@]}"
      fi
    else
      gh release upload "$tag" "$archive_path" --clobber "${repo_args[@]}"
    fi
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
