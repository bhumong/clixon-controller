# XR Domain Patch Plugin

The backend plugin removes invalid `must 'and'` XPath expressions from modules stored
under the `xr` domain directory. When a device with `<device-domain>xr</device-domain>`
connects, the plugin runs during schema parsing and strips those `must` statements so the
controller can load the Cisco IOS XR schemas without failing the XPath parser.

If the XR mount directory is empty, the plugin tries to populate it from
`${CLICON_YANG_DOMAIN_CACHE}/xr`. When the env var is unset, it falls back to
`/workspace/docker/dev/mounts/xr`.

To build/install:

```
cd extensions/plugins/xr-yang
make
make install
```
