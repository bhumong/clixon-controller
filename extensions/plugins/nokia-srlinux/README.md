# Nokia SR Linux YANG patch plugin

Backend plugin that removes all `if-feature` statements (including
`*:if-feature` extensions) from Nokia SR Linux YANG files, except for
the `srl_nokia-extensions` module which is left untouched. It also strips
`pattern` statements in the `srl_nokia-configuration-role` module to
avoid regex validation errors, and creates stub submodules for missing
`include` references. Clixon's YANG parser does not accept extension
statements inside `must` blocks, so the patch allows schema-mount parsing
and `connection open` to succeed.

At startup, the plugin scans `CLICON_YANG_DOMAIN_DIR` recursively and strips
those lines from any `.yang` file it finds. If the Nokia mount directory is
empty, it tries to populate it from `${CLICON_YANG_DOMAIN_CACHE}/nokia`.
When the env var is unset, it falls back to `/workspace/docker/dev/mounts/nokia`.

Build and install:

```
make
make install
```
