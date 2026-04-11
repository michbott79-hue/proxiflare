#include "logger.h"
#include "proxiflare.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <libgen.h>
#include <cJSON.h>

/* ──────────────────────────────────────────────────────────────────────────
 * Helpers
 * ────────────────────────────────────────────────────────────────────────── */

static void timestamp_str(time_t ts, char *buf, size_t n)
{
    struct tm tm_buf;
    localtime_r(&ts, &tm_buf);
    strftime(buf, n, "%Y-%m-%d %H:%M:%S", &tm_buf);
}

/* Extract the basename of app_path without modifying the original. */
static const char *app_basename(const char *app_path)
{
    if (!app_path || app_path[0] == '\0')
        return "unknown";

    /* strrchr is safe and avoids the POSIX basename() aliasing issues. */
    const char *slash = strrchr(app_path, '/');
    return slash ? slash + 1 : app_path;
}

/* ──────────────────────────────────────────────────────────────────────────
 * Init / Close
 * ────────────────────────────────────────────────────────────────────────── */

int pf_logger_init(pf_logger_t *log, const char *path)
{
    if (!log || !path)
        return PF_ERR;

    memset(log, 0, sizeof(*log));
    snprintf(log->log_path, sizeof(log->log_path), "%s", path);
    log->disk_enabled  = false;
    log->log_file      = NULL;
    log->max_size      = 100UL * 1024 * 1024; /* 100 MB */
    log->max_files     = 5;
    log->current_size  = 0;

    return PF_OK;
}

void pf_logger_close(pf_logger_t *log)
{
    if (!log)
        return;

    if (log->log_file) {
        fclose(log->log_file);
        log->log_file = NULL;
    }
    log->disk_enabled = false;
}

/* ──────────────────────────────────────────────────────────────────────────
 * Disk enable / disable
 * ────────────────────────────────────────────────────────────────────────── */

int pf_logger_disk_enable(pf_logger_t *log)
{
    if (!log)
        return PF_ERR;

    if (log->disk_enabled && log->log_file)
        return PF_OK; /* already open */

    log->log_file = fopen(log->log_path, "a");
    if (!log->log_file) {
        pf_log_error("logger: cannot open log file %s", log->log_path);
        return PF_ERR;
    }

    /* Measure current file size. */
    if (fseek(log->log_file, 0, SEEK_END) == 0)
        log->current_size = (size_t)ftell(log->log_file);
    else
        log->current_size = 0;

    log->disk_enabled = true;
    return PF_OK;
}

int pf_logger_disk_disable(pf_logger_t *log)
{
    if (!log)
        return PF_ERR;

    if (log->log_file) {
        fclose(log->log_file);
        log->log_file = NULL;
    }
    log->disk_enabled = false;
    return PF_OK;
}

/* ──────────────────────────────────────────────────────────────────────────
 * Rotation
 * ────────────────────────────────────────────────────────────────────────── */

int pf_logger_rotate(pf_logger_t *log)
{
    if (!log)
        return PF_ERR;

    /* Close current file. */
    if (log->log_file) {
        fclose(log->log_file);
        log->log_file = NULL;
    }

    /* Rotate in reverse order: .log.N-1 → .log.N, highest first. */
    /* +16 to silence GCC -Wformat-truncation: suffix is ".N" (1-2 chars max) */
    char old_name[PF_PATH_MAX + 16];
    char new_name[PF_PATH_MAX + 16];

    for (int i = log->max_files; i >= 1; i--) {
        if (i == 1)
            snprintf(old_name, sizeof(old_name), "%s", log->log_path);
        else
            snprintf(old_name, sizeof(old_name), "%s.%02d", log->log_path, i - 1);

        snprintf(new_name, sizeof(new_name), "%s.%02d", log->log_path, i);

        if (i == log->max_files) {
            /* Delete the oldest slot if it exists. */
            remove(new_name);
        }

        rename(old_name, new_name);
    }

    /* Open fresh log file. */
    log->log_file = fopen(log->log_path, "a");
    if (!log->log_file) {
        pf_log_error("logger: cannot reopen log file after rotation: %s", log->log_path);
        log->disk_enabled = false;
        return PF_ERR;
    }

    log->current_size = 0;
    return PF_OK;
}

/* ──────────────────────────────────────────────────────────────────────────
 * Log an entry
 * ────────────────────────────────────────────────────────────────────────── */

cJSON *pf_logger_log(pf_logger_t *log, const pf_log_entry_t *entry)
{
    if (!log || !entry)
        return NULL;

    const char *action_str = pf_action_str(entry->action);

    /* ── Disk write ─────────────────────────────────────────────────────── */
    if (log->disk_enabled && log->log_file) {
        char ts_buf[32];
        timestamp_str(entry->ts, ts_buf, sizeof(ts_buf));

        const char *app = app_basename(entry->app_path);

        int written = fprintf(log->log_file,
            "[%s] [%s:%u] %s \xe2\x86\x92 %s:%u (%s) %llu/%llu %ums\n",
            ts_buf,
            app,
            (unsigned)entry->uid,
            entry->domain,
            entry->dst_ip,
            (unsigned)entry->dst_port,
            action_str,
            (unsigned long long)entry->bytes_sent,
            (unsigned long long)entry->bytes_recv,
            (unsigned)entry->latency_ms);

        if (written > 0) {
            fflush(log->log_file);
            log->current_size += (size_t)written;

            if (log->current_size >= log->max_size)
                pf_logger_rotate(log);
        }
    }

    /* ── Build cJSON object for IPC broadcast ───────────────────────────── */
    cJSON *obj = cJSON_CreateObject();
    if (!obj)
        return NULL;

    cJSON_AddNumberToObject(obj, "ts",         (double)entry->ts);
    cJSON_AddStringToObject(obj, "app",        app_basename(entry->app_path));
    cJSON_AddNumberToObject(obj, "uid",        (double)entry->uid);
    cJSON_AddStringToObject(obj, "domain",     entry->domain);
    cJSON_AddStringToObject(obj, "dst_ip",     entry->dst_ip);
    cJSON_AddNumberToObject(obj, "dst_port",   (double)entry->dst_port);
    cJSON_AddNumberToObject(obj, "proxy_id",   (double)entry->proxy_id);
    cJSON_AddStringToObject(obj, "action",     action_str);
    cJSON_AddNumberToObject(obj, "bytes_tx",   (double)entry->bytes_sent);
    cJSON_AddNumberToObject(obj, "bytes_rx",   (double)entry->bytes_recv);
    cJSON_AddNumberToObject(obj, "latency_ms", (double)entry->latency_ms);
    cJSON_AddNumberToObject(obj, "success",    (double)entry->success);

    return obj; /* caller must cJSON_Delete() */
}

/* ──────────────────────────────────────────────────────────────────────────
 * Internal daemon logging (stderr)
 * ────────────────────────────────────────────────────────────────────────── */

static void pf_log_level(const char *level, const char *fmt, va_list ap)
{
    char ts_buf[32];
    time_t now = time(NULL);
    timestamp_str(now, ts_buf, sizeof(ts_buf));

    fprintf(stderr, "[proxiflare] [%s] [%s] ", level, ts_buf);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    fflush(stderr);
}

void pf_log_info(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    pf_log_level("INFO", fmt, ap);
    va_end(ap);
}

void pf_log_warn(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    pf_log_level("WARN", fmt, ap);
    va_end(ap);
}

void pf_log_error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    pf_log_level("ERROR", fmt, ap);
    va_end(ap);
}
