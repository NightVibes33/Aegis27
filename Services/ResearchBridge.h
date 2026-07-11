#ifndef AEGIS27_RESEARCH_BRIDGE_H
#define AEGIS27_RESEARCH_BRIDGE_H

#include <stdint.h>

int32_t aegis_sandbox_check_path(const char *operation, const char *path);
int32_t aegis_sandbox_check_global_name(const char *operation, const char *name);
int32_t aegis_bootstrap_lookup_service(const char *name);

#endif
