# NaCl Burst

NaCl Burst is a Unity Package Manager package that preserves the existing `NaCl.NaCl` API while replacing native plugin and TweetNaCl dependencies with a Burst-backed C# implementation.

The public method names intentionally keep the existing `Cyrpto*` spelling for drop-in compatibility with current callers.

## Requirements

- Unity 2022.3 or newer.
- Unity Burst 1.8.28, declared as a package dependency.
- Consumer asmdefs that already reference the `nacl` assembly can keep that reference name.

When migrating an existing project, remove the embedded `Assets/External/nacl` copy before installing this package. Keeping both copies will duplicate the `nacl` assembly and the `NaCl.NaCl` type.

## Install From A Release Tarball

Download `com.5minlab.nacl-burst-<version>.tgz` from the GitHub release assets, then in Unity use Package Manager > Add package from tarball and choose the downloaded file.

For a local project checkout, the same tarball can also be referenced from `Packages/manifest.json`:

```json
{
  "dependencies": {
    "com.5minlab.nacl-burst": "file:../path/to/com.5minlab.nacl-burst-0.1.0.tgz"
  }
}
```

## Install From Git

This package can also be imported from a Git tag if needed:

```json
{
  "dependencies": {
    "com.5minlab.nacl-burst": "https://github.com/5minlab/nacl-burst.git#v0.1.0"
  }
}
```

## Build And Publish A Release Archive

After creating and pushing the GitHub repository, run:

```bash
Tools~/release.sh pack
Tools~/release.sh release
```

`pack` creates `dist/com.5minlab.nacl-burst-<version>.tgz` with `npm pack`. `release` creates or updates the matching GitHub release asset using `gh`; set `GH_REPO=owner/nacl-burst` if the local git remote is not configured yet.
