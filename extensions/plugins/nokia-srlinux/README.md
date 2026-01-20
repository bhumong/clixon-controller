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
those lines from any `.yang` file it finds.

Note: with no core controller changes, you must prepopulate the Nokia mount
directory (for example by copying `docker/dev/mounts/nokia` into
`/usr/local/share/controller/mounts/nokia`) before starting the backend.

Build and install:

```
make
make install
```
