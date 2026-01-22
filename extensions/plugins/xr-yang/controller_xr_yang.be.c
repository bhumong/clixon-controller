/*
 * ***** BEGIN LICENSE BLOCK *****
 *
 * Copyright (C) 2026 Clixon
 *
 * This file is part of CLIXON
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * ***** END LICENSE BLOCK *****
 */

#include <ctype.h>
#include <dirent.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <limits.h>
#include <unistd.h>

#include <cligen/cligen.h>

#include <clixon/clixon.h>
#include <clixon/clixon_options.h>
#include <clixon/clixon_plugin.h>
#include <clixon/clixon_yang.h>

#include "controller.h"

#define XR_DOMAIN "xr"
#define YANG_CACHE_ENV "CLICON_YANG_DOMAIN_CACHE"
#define YANG_CACHE_DEFAULT "/workspace/docker/dev/mounts"

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
ensure_dir(const char *path,
           mode_t      mode)
{
    struct stat st;

    if (path == NULL || *path == '\0')
        return -1;
    if (stat(path, &st) == 0){
        if (S_ISDIR(st.st_mode))
            return 0;
        errno = ENOTDIR;
        return -1;
    }
    if (mkdir(path, mode) < 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int
dir_has_yang_files(const char *dir)
{
    DIR           *dp;
    struct dirent *de;
    char           path[PATH_MAX];
    struct stat    st;
    int            found = 0;

    if (dir == NULL)
        return 0;
    dp = opendir(dir);
    if (dp == NULL)
        return 0;
    while ((de = readdir(dp)) != NULL){
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        if (snprintf(path, sizeof(path), "%s/%s", dir, de->d_name) >= (int)sizeof(path))
            continue;
        if (stat(path, &st) < 0)
            continue;
        if (S_ISDIR(st.st_mode)){
            if (dir_has_yang_files(path)){
                found = 1;
                break;
            }
            continue;
        }
        if (S_ISREG(st.st_mode) && has_suffix(de->d_name, ".yang")){
            found = 1;
            break;
        }
    }
    closedir(dp);
    return found;
}

static int
copy_file(const char *src,
          const char *dst,
          mode_t      mode)
{
    FILE  *in = NULL;
    FILE  *out = NULL;
    char   buf[8192];
    size_t n;
    int    retval = -1;

    if ((in = fopen(src, "r")) == NULL)
        goto done;
    if ((out = fopen(dst, "w")) == NULL)
        goto done;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0){
        if (fwrite(buf, 1, n, out) != n)
            goto done;
    }
    if (ferror(in))
        goto done;
    if (fchmod(fileno(out), mode) < 0 && errno != EPERM)
        goto done;
    retval = 0;
done:
    if (out)
        fclose(out);
    if (in)
        fclose(in);
    return retval;
}

static int
copy_tree(const char *src,
          const char *dst)
{
    DIR           *dp = NULL;
    struct dirent *de;
    struct stat    st;
    char           srcpath[PATH_MAX];
    char           dstpath[PATH_MAX];
    int            retval = -1;

    if (stat(src, &st) < 0 || !S_ISDIR(st.st_mode))
        return -1;
    if (ensure_dir(dst, st.st_mode & 0777) < 0)
        return -1;
    if ((dp = opendir(src)) == NULL)
        return -1;
    while ((de = readdir(dp)) != NULL){
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        if (snprintf(srcpath, sizeof(srcpath), "%s/%s", src, de->d_name) >= (int)sizeof(srcpath))
            continue;
        if (snprintf(dstpath, sizeof(dstpath), "%s/%s", dst, de->d_name) >= (int)sizeof(dstpath))
            continue;
        if (stat(srcpath, &st) < 0)
            continue;
        if (S_ISDIR(st.st_mode)){
            if (copy_tree(srcpath, dstpath) < 0)
                goto done;
            continue;
        }
        if (S_ISREG(st.st_mode)){
            if (copy_file(srcpath, dstpath, st.st_mode & 0777) < 0)
                goto done;
        }
    }
    retval = 0;
done:
    if (dp)
        closedir(dp);
    return retval;
}

static int
populate_domain_from_cache(const char *domain_dir,
                           const char *domain)
{
    const char *cache_root = getenv(YANG_CACHE_ENV);
    char        srcpath[PATH_MAX];

    if (domain_dir == NULL || domain == NULL)
        return 0;
    if (dir_has_yang_files(domain_dir))
        return 0;
    if (cache_root == NULL || *cache_root == '\0')
        cache_root = YANG_CACHE_DEFAULT;
    if (snprintf(srcpath, sizeof(srcpath), "%s/%s", cache_root, domain) >= (int)sizeof(srcpath))
        return 0;
    if (copy_tree(srcpath, domain_dir) < 0){
        clixon_debug(CLIXON_DBG_APP,
                     "XR-domain-must-patch: failed to populate %s from %s",
                     domain_dir,
                     srcpath);
        return 0;
    }
    clixon_debug(CLIXON_DBG_APP,
                 "XR-domain-must-patch: populated %s from %s",
                 domain_dir,
                 srcpath);
    return 0;
}

static int
is_must_arg_and(const char *arg)
{
    char buf[16];
    size_t idx = 0;

    if (arg == NULL)
        return 0;
    while (*arg && idx + 1 < sizeof(buf)){
        unsigned char c = (unsigned char)*arg++;
        if (c == '\'' || c == '"' || isspace(c))
            continue;
        buf[idx++] = (char)tolower(c);
    }
    buf[idx] = '\0';
    return idx == 3 && strcmp(buf, "and") == 0;
}

static int
module_in_xr_domain(clixon_handle h,
                    const char  *filename)
{
    const char *domain_dir;
    const char *rest;
    size_t dirlen;
    size_t domainlen;

    if (h == NULL || filename == NULL)
        return 0;
    domain_dir = clicon_option_str(h, "CLICON_YANG_DOMAIN_DIR");
    if (domain_dir == NULL || *domain_dir == '\0')
        return 0;
    dirlen = strlen(domain_dir);
    if (strncmp(filename, domain_dir, dirlen) != 0)
        return 0;
    rest = filename + dirlen;
    if (*rest == '/')
        rest++;
    else if (*rest == '\0')
        return 0;
    domainlen = strlen(XR_DOMAIN);
    if (strncmp(rest, XR_DOMAIN, domainlen) != 0)
        return 0;
    rest += domainlen;
    return *rest == '\0' || *rest == '/';
}

static int
line_is_must_and(const char *line,
                 size_t     *indent_len)
{
    const char *p = line;
    char quote;

    if (indent_len)
        *indent_len = 0;
    if (p == NULL)
        return 0;
    while (*p && isspace((unsigned char)*p) && *p != '\n' && *p != '\r')
        p++;
    if (indent_len)
        *indent_len = (size_t)(p - line);
    if (strncmp(p, "must", 4) != 0)
        return 0;
    p += 4;
    if (!isspace((unsigned char)*p))
        return 0;
    while (*p && isspace((unsigned char)*p))
        p++;
    if (*p != '\'' && *p != '"')
        return 0;
    quote = *p++;
    if (strncmp(p, "and", 3) != 0)
        return 0;
    p += 3;
    if (*p != quote)
        return 0;
    p++;
    while (*p && isspace((unsigned char)*p))
        p++;
    if (*p != ';')
        return 0;
    p++;
    while (*p && isspace((unsigned char)*p))
        p++;
    if (*p == '\0' || *p == '\n' || *p == '\r')
        return 1;
    if (p[0] == '/' && p[1] == '/')
        return 1;
    return 0;
}

static int
read_line(FILE  *fp,
          char **line,
          size_t *cap)
{
    size_t len = 0;
    int    ch;

    if (fp == NULL || line == NULL || cap == NULL)
        return -1;
    if (*line == NULL || *cap == 0){
        *cap = 256;
        *line = malloc(*cap);
        if (*line == NULL){
            clixon_err(OE_UNIX, errno, "malloc");
            return -1;
        }
    }
    while ((ch = fgetc(fp)) != EOF){
        if (len + 1 >= *cap){
            size_t newcap = *cap * 2;
            char  *tmp = realloc(*line, newcap);
            if (tmp == NULL){
                clixon_err(OE_UNIX, errno, "realloc");
                return -1;
            }
            *line = tmp;
            *cap = newcap;
        }
        (*line)[len++] = (char)ch;
        if (ch == '\n')
            break;
    }
    if (len == 0 && ch == EOF){
        if (ferror(fp))
            return -1;
        return 1;
    }
    (*line)[len] = '\0';
    return 0;
}

static int
pattern_has_invalid_shorthand(const char *start,
                              const char *end,
                              char        quote)
{
    int prev_backslash = 0;

    while (start < end){
        char c = *start++;

        if (quote == '"' && c == '\\' && start < end)
            c = *start++;
        if (prev_backslash){
            if (c == 'w' || c == 'W' || c == 'd' || c == 'D')
                return 1;
            prev_backslash = (c == '\\');
        }
        else if (c == '\\')
            prev_backslash = 1;
    }
    return 0;
}

static int
rewrite_invalid_pattern_line(cbuf       *out,
                             const char *line,
                             int        *regex_replaced)
{
    const char *p = line;
    const char *pat_start;
    const char *pat_end = NULL;
    char        quote;

    if (out == NULL || line == NULL)
        return 0;
    while (*p && isspace((unsigned char)*p) && *p != '\n' && *p != '\r')
        p++;
    if (strncmp(p, "pattern", strlen("pattern")) != 0)
        return 0;
    p += strlen("pattern");
    if (!isspace((unsigned char)*p))
        return 0;
    while (*p && isspace((unsigned char)*p))
        p++;
    if (*p != '\'' && *p != '"')
        return 0;
    quote = *p++;
    pat_start = p;
    if (quote == '\'')
        pat_end = strchr(pat_start, '\'');
    else{
        const char *q = pat_start;

        while (*q){
            if (*q == '\\' && q[1] != '\0'){
                q += 2;
                continue;
            }
            if (*q == '"'){
                pat_end = q;
                break;
            }
            q++;
        }
    }
    if (pat_end == NULL)
        return 0;
    if (!pattern_has_invalid_shorthand(pat_start, pat_end, quote))
        return 0;
    cprintf(out, "%.*s.*%s", (int)(pat_start - line), line, pat_end);
    if (regex_replaced)
        (*regex_replaced)++;
    return 1;
}

static int
patch_yang_file(const char *path,
                int        *must_replaced,
                int        *regex_replaced)
{
    int     retval = -1;
    FILE   *fp = NULL;
    cbuf   *out = NULL;
    char   *line = NULL;
    size_t  cap = 0;
    int     changed = 0;

    if (must_replaced)
        *must_replaced = 0;
    if (regex_replaced)
        *regex_replaced = 0;
    if (path == NULL)
        return 0;
    fp = fopen(path, "r");
    if (fp == NULL)
        return 0;
    if ((out = cbuf_new()) == NULL){
        clixon_err(OE_UNIX, errno, "cbuf_new");
        goto done;
    }
    for (;;){
        int ret = read_line(fp, &line, &cap);

        if (ret != 0){
            if (ret < 0)
                goto done;
            break;
        }
        size_t indent_len = 0;

        if (line_is_must_and(line, &indent_len)){
            cprintf(out, "%.*smust 'true()';\n", (int)indent_len, line);
            changed = 1;
            if (must_replaced)
                (*must_replaced)++;
        }
        else if (rewrite_invalid_pattern_line(out, line, regex_replaced)){
            changed = 1;
        }
        else{
            cprintf(out, "%s", line);
        }
    }
    if (!changed){
        retval = 0;
        goto done;
    }
    fclose(fp);
    fp = fopen(path, "w");
    if (fp == NULL){
        clixon_err(OE_UNIX, errno, "fopen(%s)", path);
        goto done;
    }
    if (fwrite(cbuf_get(out), 1, strlen(cbuf_get(out)), fp) != strlen(cbuf_get(out))){
        clixon_err(OE_UNIX, errno, "fwrite(%s)", path);
        goto done;
    }
    retval = 0;
done:
    if (fp)
        fclose(fp);
    if (line)
        free(line);
    if (out)
        cbuf_free(out);
    return retval;
}

static int
patch_xr_domain_files(clixon_handle h)
{
    const char *domain_dir;
    char       *domain_path = NULL;
    DIR        *dir = NULL;
    struct dirent *ent;
    int         must_replaced = 0;
    int         regex_replaced = 0;

    if (h == NULL)
        return 0;
    domain_dir = clicon_option_str(h, "CLICON_YANG_DOMAIN_DIR");
    if (domain_dir == NULL || *domain_dir == '\0')
        return 0;
    {
        size_t len = strlen(domain_dir) + 1 + strlen(XR_DOMAIN) + 1;

        domain_path = malloc(len);
        if (domain_path == NULL){
            clixon_err(OE_UNIX, errno, "malloc");
            return -1;
        }
        snprintf(domain_path, len, "%s/%s", domain_dir, XR_DOMAIN);
    }
    (void)populate_domain_from_cache(domain_path, XR_DOMAIN);
    dir = opendir(domain_path);
    if (dir == NULL){
        free(domain_path);
        return 0;
    }
    while ((ent = readdir(dir)) != NULL){
        struct stat st;
        char *path = NULL;
        size_t len;
        int file_must = 0;
        int file_regex = 0;

        if (ent->d_name[0] == '.')
            continue;
        len = strlen(ent->d_name);
        if (len < 5 || strcmp(ent->d_name + len - 5, ".yang") != 0)
            continue;
        {
            size_t plen = strlen(domain_path) + 1 + strlen(ent->d_name) + 1;

            path = malloc(plen);
            if (path == NULL){
                clixon_err(OE_UNIX, errno, "malloc");
                continue;
            }
            snprintf(path, plen, "%s/%s", domain_path, ent->d_name);
        }
        if (stat(path, &st) < 0 || !S_ISREG(st.st_mode)){
            free(path);
            continue;
        }
        if (patch_yang_file(path, &file_must, &file_regex) < 0){
            free(path);
            closedir(dir);
            free(domain_path);
            return -1;
        }
        if (file_must > 0)
            must_replaced += file_must;
        if (file_regex > 0)
            regex_replaced += file_regex;
        free(path);
    }
    closedir(dir);
    free(domain_path);
    if (must_replaced > 0 || regex_replaced > 0)
        clixon_debug(CLIXON_DBG_CTRL,
                     "XR-domain-must-patch: rewrote %d must 'and' and %d invalid pattern statements in %s",
                     must_replaced, regex_replaced, domain_dir);
    return 0;
}

static int
module_is_xr(clixon_handle h,
             yang_stmt   *ymod)
{
    const char *filename;
    const char *modname;

    if (ymod == NULL)
        return 0;
    filename = yang_filename_get(ymod);
    if (filename && module_in_xr_domain(h, filename))
        return 1;
    modname = yang_argument_get(ymod);
    if (modname == NULL)
        return 0;
    if (strncmp(modname, "Cisco-IOS-XR-", strlen("Cisco-IOS-XR-")) == 0)
        return 1;
    if (strncmp(modname, "cisco-xr-", strlen("cisco-xr-")) == 0)
        return 1;
    return 0;
}

struct must_list {
    yang_stmt **items;
    size_t      len;
    size_t      cap;
};

static int
must_list_add(struct must_list *ml,
              yang_stmt        *ys)
{
    size_t newcap;
    yang_stmt **items;

    if (ml->len == ml->cap){
        newcap = ml->cap ? ml->cap * 2 : 16;
        items = realloc(ml->items, newcap * sizeof(*items));
        if (items == NULL){
            clixon_err(OE_UNIX, errno, "realloc");
            return -1;
        }
        ml->items = items;
        ml->cap = newcap;
    }
    ml->items[ml->len++] = ys;
    return 0;
}

static int
collect_musts(yang_stmt *ys,
              void      *arg)
{
    struct must_list *ml = arg;

    if (is_must_arg_and(yang_argument_get(ys)))
        return must_list_add(ml, ys);
    return 0;
}

static int
remove_invalid_musts(yang_stmt *ys,
                     int       *removed)
{
    struct must_list ml = {0};
    size_t i;

    if (ys == NULL || removed == NULL)
        return 0;
    if (yang_apply(ys, Y_MUST, collect_musts, -1, &ml) < 0)
        goto fail;
    for (i = 0; i < ml.len; i++){
        if (ys_prune_self(ml.items[i]) < 0)
            goto fail;
        if (ys_free(ml.items[i]) < 0)
            goto fail;
        (*removed)++;
    }
    free(ml.items);
    return 0;
fail:
    free(ml.items);
    return -1;
}

static int
xr_yang(clixon_handle h,
              yang_stmt   *ymod)
{
    const char *filename;
    const char *modname;
    int         removed = 0;

    if (h == NULL || ymod == NULL)
        return 0;
    if (!module_is_xr(h, ymod))
        return 0;
    filename = yang_filename_get(ymod);
    modname = yang_argument_get(ymod);
    if (modname && strcmp(modname, "Cisco-IOS-XR-um-router-pim-cfg") == 0)
        clixon_debug(CLIXON_DBG_CTRL,
                     "XR-domain-must-patch: inspecting %s (%s)",
                     modname, filename ? filename : "no-file");
    if (remove_invalid_musts(ymod, &removed) < 0)
        return -1;
    if (removed > 0)
        clixon_debug(CLIXON_DBG_CTRL, "XR-domain-must-patch: removed %d invalid must statements from %s",
                     removed, filename);
    return 0;
}

static clixon_plugin_api api = {
    "xr-domain-must-patch",
    .ca_yang_patch = xr_yang,
};

clixon_plugin_api *
clixon_plugin_init(clixon_handle h)
{
    if (patch_xr_domain_files(h) < 0)
        clixon_err(OE_PLUGIN, 0, "XR-domain-must-patch: failed to pre-patch YANG files");
    return &api;
}
