#ifndef PF_LOGGER_H
#define PF_LOGGER_H

#include "proxiflare.h"
#include <stdio.h>
#include <stdbool.h>
#include <cJSON.h>

typedef struct {
    bool   disk_enabled;
    char   log_path[PF_PATH_MAX];
    FILE  *log_file;
    size_t max_size;      /* bytes, default 100MB */
    int    max_files;     /* rotation count, default 5 */
    size_t current_size;
} pf_logger_t;

int    pf_logger_init(pf_logger_t *log, const char *path);
void   pf_logger_close(pf_logger_t *log);
int    pf_logger_disk_enable(pf_logger_t *log);
int    pf_logger_disk_disable(pf_logger_t *log);
cJSON *pf_logger_log(pf_logger_t *log, const pf_log_entry_t *entry);
int    pf_logger_rotate(pf_logger_t *log);

/* Daemon internal logging to stderr */
void pf_log_info(const char *fmt, ...);
void pf_log_warn(const char *fmt, ...);
void pf_log_error(const char *fmt, ...);

#endif /* PF_LOGGER_H */
