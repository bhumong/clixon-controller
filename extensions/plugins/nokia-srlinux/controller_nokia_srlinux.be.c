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
#define YANG_CACHE_ENV "CLICON_YANG_DOMAIN_CACHE"
#define YANG_CACHE_DEFAULT "/workspace/docker/dev/mounts"

static int has_suffix(const char *str, const char *suffix);
static int list_contains(char **list, size_t len, const char *name);
static int list_add(char ***list, size_t *len, const char *name);
static void list_free(char **list, size_t len);

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
                     "nokia-srlinux: failed to populate %s from %s",
                     domain_dir,
                     srcpath);
        return 0;
    }
    clixon_debug(CLIXON_DBG_APP,
                 "nokia-srlinux: populated %s from %s",
                 domain_dir,
                 srcpath);
    return 0;
}

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
list_contains(char **list,
              size_t len,
              const char *name)
{
    size_t i;

    if (list == NULL || name == NULL)
        return 0;
    for (i = 0; i < len; i++){
        if (list[i] && strcmp(list[i], name) == 0)
            return 1;
    }
    return 0;
}

static int
list_add(char ***list,
         size_t *len,
         const char *name)
{
    char  *dup;
    char **tmp;

    if (list == NULL || len == NULL || name == NULL)
        return -1;
    if (list_contains(*list, *len, name))
        return 0;
    dup = strdup(name);
    if (dup == NULL)
        return -1;
    tmp = realloc(*list, (*len + 1) * sizeof(**list));
    if (tmp == NULL){
        free(dup);
        return -1;
    }
    *list = tmp;
    (*list)[*len] = dup;
    (*len)++;
    return 0;
}

static void
list_free(char **list,
          size_t len)
{
    size_t i;

    if (list == NULL)
        return;
    for (i = 0; i < len; i++)
        free(list[i]);
    free(list);
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
find_submodule_path(const char *dir,
                    const char *name,
                    char       *out,
                    size_t      outlen)
{
    DIR           *dp;
    struct dirent *de;
    size_t         namelen;

    if (dir == NULL || name == NULL || out == NULL || outlen == 0)
        return -1;
    namelen = strlen(name);
    if (namelen == 0)
        return -1;
    if (snprintf(out, outlen, "%s/%s.yang", dir, name) < (int)outlen &&
        access(out, F_OK) == 0)
        return 0;
    dp = opendir(dir);
    if (dp == NULL)
        return -1;
    while ((de = readdir(dp)) != NULL){
        if (strncmp(de->d_name, name, namelen) != 0)
            continue;
        if (de->d_name[namelen] != '@')
            continue;
        if (!has_suffix(de->d_name, ".yang"))
            continue;
        if (snprintf(out, outlen, "%s/%s", dir, de->d_name) >= (int)outlen)
            continue;
        closedir(dp);
        return 0;
    }
    closedir(dp);
    return -1;
}

static int
collect_groupings_from_file(const char *path,
                            char      ***groupings,
                            size_t     *groupings_len)
{
    FILE   *fp;
    char   *line = NULL;
    size_t  cap = 0;
    int     retval = -1;

    if (path == NULL || groupings == NULL || groupings_len == NULL)
        return 0;
    if ((fp = fopen(path, "r")) == NULL)
        return 0;
    while (getline(&line, &cap, fp) != -1){
        char token[128];

        if (parse_keyword_arg(line, strlen(line), "grouping", token, sizeof(token))){
            if (list_add(groupings, groupings_len, token) < 0)
                goto done;
        }
    }
    if (ferror(fp))
        goto done;
    retval = 0;
done:
    if (fp)
        fclose(fp);
    free(line);
    return retval;
}

static int
collect_groupings_from_includes(const char *dir,
                                char      **includes,
                                size_t      include_len,
                                char      ***groupings,
                                size_t     *groupings_len)
{
    size_t i;

    if (dir == NULL || includes == NULL || groupings == NULL || groupings_len == NULL)
        return 0;
    for (i = 0; i < include_len; i++){
        char path[PATH_MAX];

        if (includes[i] == NULL || includes[i][0] == '\0')
            continue;
        if (find_submodule_path(dir, includes[i], path, sizeof(path)) < 0)
            continue;
        if (collect_groupings_from_file(path, groupings, groupings_len) < 0)
            return -1;
    }
    return 0;
}

static int
add_groupings_to_submodule(const char *dir,
                           const char *name,
                           char      **groupings,
                           size_t      groupings_len)
{
    char         path[PATH_MAX];
    char         tmp[PATH_MAX];
    struct stat  st;
    FILE        *fp = NULL;
    char        *buf = NULL;
    long         sz = 0;
    size_t       end;
    size_t       i;
    cbuf        *out = NULL;
    char       **existing = NULL;
    size_t       existing_len = 0;
    int          add = 0;
    int          retval = -1;

    tmp[0] = '\0';
    if (groupings == NULL || groupings_len == 0)
        return 0;
    if (find_submodule_path(dir, name, path, sizeof(path)) < 0)
        return 0;
    if (stat(path, &st) < 0)
        return -1;
    if ((fp = fopen(path, "r")) == NULL)
        return -1;
    if (fseek(fp, 0, SEEK_END) < 0)
        goto done;
    sz = ftell(fp);
    if (sz < 0)
        goto done;
    if (fseek(fp, 0, SEEK_SET) < 0)
        goto done;
    buf = malloc((size_t)sz + 1);
    if (buf == NULL)
        goto done;
    if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz)
        goto done;
    buf[sz] = '\0';
    fclose(fp);
    fp = NULL;

    {
        char *line = NULL;
        char *cursor = buf;
        char *next;

        while ((next = strchr(cursor, '\n')) != NULL){
            size_t len = (size_t)(next - cursor + 1);

            free(line);
            line = strndup(cursor, len);
            if (line == NULL)
                break;
            if (parse_keyword_arg(line, len, "grouping", line, len))
                list_add(&existing, &existing_len, line);
            cursor = next + 1;
        }
        free(line);
    }

    for (i = 0; i < groupings_len; i++){
        if (!list_contains(existing, existing_len, groupings[i])){
            add = 1;
            break;
        }
    }
    if (!add){
        retval = 0;
        goto done;
    }
    end = (size_t)sz;
    while (end > 0 && isspace((unsigned char)buf[end - 1]))
        end--;
    if (end == 0 || buf[end - 1] != '}'){
        retval = 0;
        goto done;
    }
    if ((out = cbuf_new()) == NULL)
        goto done;
    cprintf(out, "%.*s", (int)(end - 1), buf);
    if (end >= 2 && buf[end - 2] != '\n')
        cprintf(out, "\n");
    for (i = 0; i < groupings_len; i++){
        if (list_contains(existing, existing_len, groupings[i]))
            continue;
        cprintf(out, "  grouping %s {\n", groupings[i]);
        cprintf(out, "  }\n");
    }
    cprintf(out, "}\n");
    if (snprintf(tmp, sizeof(tmp), "%s.clixon_tmp", path) >= (int)sizeof(tmp))
        goto done;
    if ((fp = fopen(tmp, "w")) == NULL)
        goto done;
    if (fwrite(cbuf_get(out), 1, strlen(cbuf_get(out)), fp) != strlen(cbuf_get(out)))
        goto done;
    if (fflush(fp) != 0)
        goto done;
    if (fsync(fileno(fp)) < 0)
        goto done;
    if (fchmod(fileno(fp), st.st_mode) < 0 && errno != EPERM)
        goto done;
    if (fchown(fileno(fp), st.st_uid, st.st_gid) < 0 && errno != EPERM)
        goto done;
    fclose(fp);
    fp = NULL;
    if (rename(tmp, path) < 0)
        goto done;
    retval = 0;
done:
    if (fp)
        fclose(fp);
    if (tmp[0] != '\0')
        unlink(tmp);
    if (out)
        cbuf_free(out);
    list_free(existing, existing_len);
    free(buf);
    return retval;
}

static int
ensure_submodule_stub(const char *dir,
                      const char *name,
                      const char *module,
                      const char *prefix,
                      mode_t      mode,
                      char      **groupings,
                      size_t      groupings_len)
{
    FILE *f;
    char  path[PATH_MAX];
    size_t i;

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
    for (i = 0; i < groupings_len; i++){
        if (groupings[i] == NULL || groupings[i][0] == '\0')
            continue;
        fprintf(f, "  grouping %s {\n", groupings[i]);
        fprintf(f, "  }\n");
    }
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
                  mode_t      mode,
                  char      **missing_groupings,
                  size_t      missing_len)
{
    const char *slash;
    char        dir[PATH_MAX];
    size_t      i;
    int         wrote_groupings = 0;

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
        char      **grp = NULL;
        size_t      grp_len = 0;

        if (name == NULL || name[0] == '\0')
            continue;
        if (submodule_exists(dir, name)){
            if (!wrote_groupings && missing_len > 0){
                if (add_groupings_to_submodule(dir, name,
                                               missing_groupings,
                                               missing_len) < 0)
                    return -1;
                wrote_groupings = 1;
            }
            continue;
        }
        if (!wrote_groupings && missing_len > 0){
            grp = missing_groupings;
            grp_len = missing_len;
            wrote_groupings = 1;
        }
        if (ensure_submodule_stub(dir, name, module, prefix, mode, grp, grp_len) < 0)
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
    char      **groupings = NULL;
    size_t      groupings_len = 0;
    char      **uses = NULL;
    size_t      uses_len = 0;
    char      **missing_groupings = NULL;
    size_t      missing_len = 0;
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
        if (parse_keyword_arg(line, (size_t)linelen, "grouping", token, sizeof(token))){
            if (list_add(&groupings, &groupings_len, token) < 0)
                goto done;
        }
        if (parse_keyword_arg(line, (size_t)linelen, "uses", token, sizeof(token))){
            if (strchr(token, ':') == NULL){
                if (list_add(&uses, &uses_len, token) < 0)
                    goto done;
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
        const char *slash;
        char        dir[PATH_MAX];

        if (!have_prefix)
            snprintf(module_prefix, sizeof(module_prefix), "%s", module_name);
        slash = strrchr(path, '/');
        if (slash != NULL && (size_t)(slash - path) < sizeof(dir)){
            memcpy(dir, path, (size_t)(slash - path));
            dir[slash - path] = '\0';
            if (collect_groupings_from_includes(dir, includes, include_len,
                                                &groupings, &groupings_len) < 0)
                goto done;
        }
        if (uses){
            size_t i;

            for (i = 0; i < uses_len; i++){
                if (!list_contains(groupings, groupings_len, uses[i])){
                    if (list_add(&missing_groupings, &missing_len, uses[i]) < 0)
                        goto done;
                }
            }
        }
        if (ensure_submodules(path, module_name, module_prefix, includes, include_len,
                              st.st_mode, missing_groupings, missing_len) < 0)
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
    list_free(groupings, groupings_len);
    list_free(uses, uses_len);
    list_free(missing_groupings, missing_len);
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
    (void)populate_domain_from_cache(cbuf_get(cb), "nokia");
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
