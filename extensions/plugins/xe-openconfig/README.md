# XE OpenConfig plugin

Backend plugin for Cisco XE devices that removes the
`openconfig-if-ethernet` subtree on outgoing edit-config operations.

This avoids device-side failures on the `when` condition that references
`/interfaces/interface/state/type` during edit-config.

Configuration:
- Set `device-domain` to `xe` for the target devices so the plugin
  applies only to XE devices.

Build/install:
```
cd xe-openconfig
make
make install
```
