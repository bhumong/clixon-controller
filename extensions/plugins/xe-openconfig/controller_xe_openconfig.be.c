/*
 *
  ***** BEGIN LICENSE BLOCK *****

  Copyright (C) 2025 Olof Hagsand

  This file is part of CLIXON.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  ***** END LICENSE BLOCK *****
  *
  * Cisco XE OpenConfig adjustments
  */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>

/* clicon */
#include <cligen/cligen.h>

/* Clicon library functions. */
#include <clixon/clixon.h>
#include <clixon/clixon_xml_nsctx.h>

/* These include signatures for plugin and transaction callbacks. */
#include <clixon/clixon_backend.h>

/* Controller includes */
#include "controller.h"
#include "controller_lib.h"
#include "controller_device_state.h"
#include "controller_device_handle.h"

static int
xe_openconfig_remove(cxobj *xdata,
                     const char *xpath)
{
    int     retval = -1;
    cvec   *nsc = NULL;
    cxobj **vec = NULL;
    size_t  veclen = 0;
    size_t  i;

    nsc = xml_nsctx_init("oc-if", "http://openconfig.net/yang/interfaces");
    if (nsc == NULL)
        goto done;
    if (xml_nsctx_add(nsc, "oc-eth", "http://openconfig.net/yang/interfaces/ethernet") < 0)
        goto done;
    if (xml_nsctx_add(nsc, "oc-ni", "http://openconfig.net/yang/network-instance") < 0)
        goto done;
    if (xpath_vec(xdata, nsc, "%s", &vec, &veclen, xpath) < 0)
        goto done;
    if (veclen == 0)
        clixon_debug(CLIXON_DBG_CTRL, "xe-openconfig: no match for %s", xpath);
    for (i = 0; i < veclen; i++){
        xml_purge(vec[i]);
        clixon_debug(CLIXON_DBG_CTRL, "xe-openconfig: removed %s", xpath);
    }
    retval = 0;
 done:
    if (vec)
        free(vec);
    if (nsc)
        xml_nsctx_free(nsc);
    return retval;
}

static int
xe_openconfig_modify_send(device_handle dh,
                          cxobj        *xdata)
{
    int         retval = -1;
    const char *domain;
    const char *name;

    domain = device_handle_domain_get(dh);
    name = device_handle_name_get(dh);
    if ((domain == NULL || strcmp(domain, "xe") != 0) &&
        (name == NULL || strcmp(name, "xe") != 0))
        goto ok;

    if (xe_openconfig_remove(xdata, "//oc-if:interfaces/oc-if:interface/oc-eth:ethernet") < 0)
        goto done;
    if (xe_openconfig_remove(xdata, "//oc-ni:network-instances/oc-ni:network-instance/oc-ni:config/oc-ni:enabled-address-families") < 0)
        goto done;

 ok:
    retval = 0;
 done:
    return retval;
}

static int
xe_openconfig_modify_recv(device_handle dh,
                          cxobj        *xdata)
{
    int         retval = -1;
    const char *domain;

    domain = device_handle_domain_get(dh);
    if ((domain == NULL || strcmp(domain, "xe") != 0))
        goto ok;

    if (xe_openconfig_remove(xdata, "//oc-if:interfaces/oc-if:interface/oc-eth:ethernet") < 0)
        goto done;
    if (xe_openconfig_remove(xdata, "//oc-ni:network-instances/oc-ni:network-instance/oc-ni:config/oc-ni:enabled-address-families") < 0)
        goto done;

 ok:
    retval = 0;
 done:
    return retval;
}

static int
xe_openconfig_userdef(clixon_handle h,
                      int           type,
                      cxobj        *xn,
                      void         *arg)
{
    int           retval = -1;
    device_handle dh = (device_handle)arg;
    const char   *domain = NULL;
    const char   *name = NULL;

    if (xn == NULL || dh == NULL){
        clixon_err(OE_PLUGIN, EINVAL, "xn or dh is NULL");
        goto done;
    }
    domain = device_handle_domain_get(dh);
    name = device_handle_name_get(dh);
    clixon_debug(CLIXON_DBG_CTRL, "xe-openconfig: userdef type:%d name:%s domain:%s",
                 type,
                 name ? name : "(null)",
                 domain ? domain : "(null)");
    switch (type){
    case CTRL_NX_RECV:
        if (xe_openconfig_modify_recv(dh, xn) < 0)
            goto done;
        break;
    case CTRL_NX_SEND:
        if (xe_openconfig_modify_send(dh, xn) < 0)
            goto done;
        break;
    default:
        break;
    }
    retval = 0;
 done:
    return retval;
}

clixon_plugin_api *clixon_plugin_init(clixon_handle h);

static clixon_plugin_api api = {
    "xe-openconfig",
    .ca_userdef      = xe_openconfig_userdef,
};

clixon_plugin_api *
clixon_plugin_init(clixon_handle h)
{
    return &api;
}
