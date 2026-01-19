# XR Domain Patch Plugin

The backend plugin removes invalid `must 'and'` XPath expressions from modules stored
under the `xr` domain directory. When a device with `<device-domain>xr</device-domain>`
connects, the plugin runs during schema parsing and strips those `must` statements so the
controller can load the Cisco IOS XR schemas without failing the XPath parser.

To build/install:

```
cd extensions/plugins/xr-domain-must-fix
make
make install
```
