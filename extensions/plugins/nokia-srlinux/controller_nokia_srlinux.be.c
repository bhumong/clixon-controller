#define _POSIX_C_SOURCE 200809L
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
  * Nokia SR Linux YANG patch plugin
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stddef.h>
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cligen/cligen.h>
#include <clixon/clixon.h>
#include <clixon/clixon_backend.h>

#define IF_FEATURE_TOKEN "if-feature"
#define EXTENSIONS_MODULE "srl_nokia-extensions"
#define CONFIG_ROLE_MODULE "srl_nokia-configuration-role"

static int
has_suffix(const char *str,
           const char *suffix)
{
    size_t len;
    size_t slen;

    if (str == NULL || suffix == NULL)
        return 0;
    len = strlen(str);
    slen = strlen(suffix);
    if (slen > len)
        return 0;
    return strcmp(str + (len - slen), suffix) == 0;
}

static int
line_is_if_feature_stmt(const char *line,
                        size_t      len)
{
    const char *p;
    const char *end;
    const char *tok_end;
    const char *ifp;
    size_t      tok_len;

    if (line == NULL || len == 0)
        return 0;
    p = line;
    end = line + len;
    while (p < end && isspace((unsigned char)*p))
        p++;
    if (p >= end)
        return 0;
    if (strncmp(p, "extension", strlen("extension")) == 0)
        return 0;
    if (strncmp(p, IF_FEATURE_TOKEN, strlen(IF_FEATURE_TOKEN)) == 0){
        char next = p[strlen(IF_FEATURE_TOKEN)];
        if (next == '\0' || isspace((unsigned char)next) || next == '"' ||
            next == '\'' || next == ';' || next == '{')
            return 1;
    }
    tok_end = p;
    while (tok_end < end && !isspace((unsigned char)*tok_end) &&
           *tok_end != ';' && *tok_end != '{')
        tok_end++;
    tok_len = (size_t)(tok_end - p);
    if (tok_len >= strlen(":if-feature")){
        ifp = strstr(p, ":if-feature");
        if (ifp && ifp + strlen(":if-feature") == tok_end)
            return 1;
    }
    return 0;
}

static int
line_is_pattern_stmt(const char *line,
                     size_t      len)
{
    const char *p;
    const char *end;
    size_t      toklen;

    if (line == NULL || len == 0)
        return 0;
    p = line;
    end = line + len;
    while (p < end && isspace((unsigned char)*p))
        p++;
    if (p >= end)
        return 0;
    toklen = strlen("pattern");
    if (p + toklen > end)
        return 0;
    if (strncmp(p, "pattern", toklen) != 0)
        return 0;
    if (p + toklen == end)
        return 1;
    if (isspace((unsigned char)p[toklen]) || p[toklen] == '"' ||
        p[toklen] == '\'' || p[toklen] == ';' || p[toklen] == '{')
        return 1;
    return 0;
}

static int
is_module_path(const char *path,
               const char *module)
{
    const char *base;
    size_t      modlen;
    char        next;

    if (path == NULL || module == NULL)
        return 0;
    base = strrchr(path, '/');
    base = base ? base + 1 : path;
    modlen = strlen(module);
    if (strncmp(base, module, modlen) != 0)
        return 0;
    next = base[modlen];
    if (next == '\0' || next == '@' || next == '.' || isspace((unsigned char)next))
        return 1;
    return 0;
}

static int
parse_keyword_arg(const char *line,
                  size_t      len,
                  const char *keyword,
                  char       *out,
                  size_t      outlen)
{
    const char *p;
    const char *end;
    size_t      klen;

    if (line == NULL || keyword == NULL || out == NULL || outlen == 0)
        return 0;
    p = line;
    end = line + len;
    while (p < end && isspace((unsigned char)*p))
        p++;
    klen = strlen(keyword);
    if ((size_t)(end - p) < klen)
        return 0;
    if (strncmp(p, keyword, klen) != 0)
        return 0;
    p += klen;
    if (p < end && !isspace((unsigned char)*p))
        return 0;
    while (p < end && isspace((unsigned char)*p))
        p++;
    if (p >= end)
        return 0;
    {
        const char *start = p;
        size_t      tlen;

        while (p < end && !isspace((unsigned char)*p) &&
               *p != ';' && *p != '{' && *p != '\r' && *p != '\n')
            p++;
        tlen = (size_t)(p - start);
        if (tlen == 0)
            return 0;
        if (tlen >= outlen)
            tlen = outlen - 1;
        memcpy(out, start, tlen);
        out[tlen] = '\0';
    }
    return 1;
}

static int
submodule_exists(const char *dir,
                 const char *name)
{
    DIR           *dp = NULL;
    struct dirent *de;
    size_t         namelen;

    if (dir == NULL || name == NULL)
        return 0;
    namelen = strlen(name);
    if (namelen == 0)
        return 0;
    {
        char path[PATH_MAX];

        if (snprintf(path, sizeof(path), "%s/%s.yang", dir, name) >= (int)sizeof(path))
            return 0;
        if (access(path, F_OK) == 0)
            return 1;
    }
    if ((dp = opendir(dir)) == NULL)
        return 0;
    while ((de = readdir(dp)) != NULL){
        if (strncmp(de->d_name, name, namelen) != 0)
            continue;
        if (de->d_name[namelen] != '@')
            continue;
        if (!has_suffix(de->d_name, ".yang"))
            continue;
        closedir(dp);
        return 1;
    }
    closedir(dp);
    return 0;
}

static int
ensure_submodule_stub(const char *dir,
                      const char *name,
                      const char *module,
                      const char *prefix,
                      mode_t      mode)
{
    FILE *f;
    char  path[PATH_MAX];

    if (snprintf(path, sizeof(path), "%s/%s.yang", dir, name) >= (int)sizeof(path)){
        clixon_err(OE_UNIX, ENAMETOOLONG, "submodule path %s/%s.yang", dir, name);
        return -1;
    }
    if ((f = fopen(path, "w")) == NULL){
        clixon_err(OE_UNIX, errno, "fopen %s", path);
        return -1;
    }
    fprintf(f, "submodule %s {\n", name);
    fprintf(f, "  belongs-to %s {\n", module);
    fprintf(f, "    prefix %s;\n", prefix);
    fprintf(f, "  }\n");
    fprintf(f, "}\n");
    fclose(f);
    if (chmod(path, mode) < 0)
        clixon_debug(CLIXON_DBG_APP, "chmod %s failed: %s", path, strerror(errno));
    return 0;
}

static int
ensure_submodules(const char *path,
                  const char *module,
                  const char *prefix,
                  char      **includes,
                  size_t      include_len,
                  mode_t      mode)
{
    const char *slash;
    char        dir[PATH_MAX];
    size_t      i;

    if (path == NULL || module == NULL || prefix == NULL)
        return 0;
    slash = strrchr(path, '/');
    if (slash == NULL)
        return 0;
    if ((size_t)(slash - path) >= sizeof(dir))
        return 0;
    memcpy(dir, path, (size_t)(slash - path));
    dir[slash - path] = '\0';
    for (i = 0; i < include_len; i++){
        const char *name = includes[i];

        if (name == NULL || name[0] == '\0')
            continue;
        if (submodule_exists(dir, name))
            continue;
        if (ensure_submodule_stub(dir, name, module, prefix, mode) < 0)
            return -1;
        clixon_debug(CLIXON_DBG_APP, "Created stub submodule %s.yang", name);
    }
    return 0;
}

static int
sanitize_if_feature_line_to_file(FILE       *dst,
                                 const char *line,
                                 size_t      len,
                                 int        *changed)
{
    if (line_is_if_feature_stmt(line, len)){
        if (changed)
            *changed = 1;
        return 0;
    }
    if (fwrite(line, 1, len, dst) != len){
        clixon_err(OE_UNIX, errno, "fwrite");
        return -1;
    }
    return 0;
}

static int
patch_yang_file(const char *path)
{
    int         retval = -1;
    FILE       *src = NULL;
    FILE       *dst = NULL;
    struct stat st;
    char       *line = NULL;
    size_t      linecap = 0;
    ssize_t     linelen;
    int         changed = 0;
    int         strip_patterns = 0;
    int         have_module = 0;
    int         have_prefix = 0;
    int         is_submodule = 0;
    char        module_name[128] = {0};
    char        module_prefix[128] = {0};
    char      **includes = NULL;
    size_t      include_len = 0;
    char        tmp[PATH_MAX];

    tmp[0] = '\0';
    if (is_module_path(path, EXTENSIONS_MODULE))
        return 0;
    if (is_module_path(path, CONFIG_ROLE_MODULE))
        strip_patterns = 1;
    if (stat(path, &st) < 0){
        clixon_err(OE_UNIX, errno, "stat %s", path);
        goto done;
    }
    if ((src = fopen(path, "r")) == NULL){
        clixon_err(OE_UNIX, errno, "fopen %s", path);
        goto done;
    }
    if (snprintf(tmp, sizeof(tmp), "%s.clixon_tmp", path) >= (int)sizeof(tmp)){
        clixon_err(OE_UNIX, ENAMETOOLONG, "tmp path for %s", path);
        goto done;
    }
    if ((dst = fopen(tmp, "w")) == NULL){
        clixon_err(OE_UNIX, errno, "fopen %s", tmp);
        goto done;
    }
    if (fchmod(fileno(dst), st.st_mode) < 0)
        clixon_debug(CLIXON_DBG_APP, "chmod %s failed: %s", tmp, strerror(errno));
    if (fchown(fileno(dst), st.st_uid, st.st_gid) < 0 && errno != EPERM)
        clixon_debug(CLIXON_DBG_APP, "chown %s failed: %s", tmp, strerror(errno));

    while ((linelen = getline(&line, &linecap, src)) != -1){
        char token[128];

        if (!have_module &&
            parse_keyword_arg(line, (size_t)linelen, "module", token, sizeof(token))){
            snprintf(module_name, sizeof(module_name), "%s", token);
            have_module = 1;
        }
        else if (!have_module &&
                 parse_keyword_arg(line, (size_t)linelen, "submodule", token, sizeof(token))){
            snprintf(module_name, sizeof(module_name), "%s", token);
            have_module = 1;
            is_submodule = 1;
        }
        if (!have_prefix && have_module &&
            parse_keyword_arg(line, (size_t)linelen, "prefix", token, sizeof(token))){
            snprintf(module_prefix, sizeof(module_prefix), "%s", token);
            have_prefix = 1;
        }
        if (parse_keyword_arg(line, (size_t)linelen, "include", token, sizeof(token))){
            size_t i;
            int found = 0;

            for (i = 0; i < include_len; i++){
                if (strcmp(includes[i], token) == 0){
                    found = 1;
                    break;
                }
            }
            if (!found){
                char *dup = strdup(token);
                char **tmpv;

                if (dup == NULL){
                    clixon_err(OE_UNIX, errno, "strdup");
                    goto done;
                }
                tmpv = realloc(includes, (include_len + 1) * sizeof(*includes));
                if (tmpv == NULL){
                    clixon_err(OE_UNIX, errno, "realloc");
                    free(dup);
                    goto done;
                }
                includes = tmpv;
                includes[include_len++] = dup;
            }
        }
        if (strip_patterns && line_is_pattern_stmt(line, (size_t)linelen)){
            changed = 1;
            continue;
        }
        if (sanitize_if_feature_line_to_file(dst, line, (size_t)linelen, &changed) < 0)
            goto done;
    }
    if (ferror(src)){
        clixon_err(OE_UNIX, errno, "fread %s", path);
        goto done;
    }
    if (!is_submodule && have_module && include_len > 0){
        if (!have_prefix)
            snprintf(module_prefix, sizeof(module_prefix), "%s", module_name);
        if (ensure_submodules(path, module_name, module_prefix, includes, include_len, st.st_mode) < 0)
            goto done;
    }
    if (!changed){
        retval = 0;
        goto done;
    }
    if (fflush(dst) != 0){
        clixon_err(OE_UNIX, errno, "fflush %s", tmp);
        goto done;
    }
    if (fsync(fileno(dst)) < 0){
        clixon_err(OE_UNIX, errno, "fsync %s", tmp);
        goto done;
    }
    if (rename(tmp, path) < 0){
        clixon_err(OE_UNIX, errno, "rename %s -> %s", tmp, path);
        goto done;
    }
    clixon_debug(CLIXON_DBG_APP, "Patched YANG file %s", path);
    retval = 1;
 done:
    if (dst)
        fclose(dst);
    if (src)
        fclose(src);
    if (includes){
        size_t i;

        for (i = 0; i < include_len; i++)
            free(includes[i]);
        free(includes);
    }
    if (line)
        free(line);
    if (retval <= 0 && tmp[0] != '\0')
        unlink(tmp);
    return retval;
}


static int
patch_yang_dir(const char *dir)
{
    int            retval = 0;
    DIR           *dp = NULL;
    struct dirent *de;
    char           path[PATH_MAX];
    struct stat    st;

    if ((dp = opendir(dir)) == NULL){
        if (errno == ENOENT)
            return 0;
        clixon_err(OE_UNIX, errno, "opendir %s", dir);
        return -1;
    }
    while ((de = readdir(dp)) != NULL){
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        if (snprintf(path, sizeof(path), "%s/%s", dir, de->d_name) >= (int)sizeof(path)){
            clixon_err(OE_UNIX, ENAMETOOLONG, "path %s/%s", dir, de->d_name);
            retval = -1;
            continue;
        }
        if (lstat(path, &st) < 0){
            clixon_err(OE_UNIX, errno, "lstat %s", path);
            retval = -1;
            continue;
        }
        if (S_ISDIR(st.st_mode)){
            if (patch_yang_dir(path) < 0)
                retval = -1;
            continue;
        }
        if (!S_ISREG(st.st_mode))
            continue;
        if (!has_suffix(de->d_name, ".yang"))
            continue;
        if (patch_yang_file(path) < 0)
            retval = -1;
    }
    closedir(dp);
    return retval;
}

static int
nokia_srlinux_start(clixon_handle h)
{
    int   retval = -1;
    char *dir;
    cbuf *cb = NULL;

    if ((dir = clicon_yang_domain_dir(h)) == NULL){
        clixon_err(OE_YANG, 0, "CLICON_YANG_DOMAIN_DIR not set");
        goto done;
    }
    if ((cb = cbuf_new()) == NULL){
        clixon_err(OE_UNIX, errno, "cbuf_new");
        goto done;
    }
    cprintf(cb, "%s/nokia", dir);
    retval = patch_yang_dir(cbuf_get(cb));
 done:
    if (cb)
        cbuf_free(cb);
    return retval;
}

clixon_plugin_api *clixon_plugin_init(clixon_handle h);

static clixon_plugin_api api = {
    "nokia-srlinux",
    .ca_start = nokia_srlinux_start,
};

clixon_plugin_api *
clixon_plugin_init(clixon_handle h)
{
    return &api;
}
