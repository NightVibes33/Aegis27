#ifndef AEGIS27_RESEARCH_BRIDGE_H
#define AEGIS27_RESEARCH_BRIDGE_H

#include <stdint.h>

int32_t aegis_sandbox_check_path(const char *operation, const char *path);
int32_t aegis_sandbox_check_global_name(const char *operation, const char *name);
int32_t aegis_bootstrap_lookup_service(const char *name);
int32_t aegis_bootstrap_probe_service(
    const char *name,
    uint32_t *port_type,
    uint32_t *send_right_refs
);
int32_t aegis_xpc_empty_dictionary_probe(
    const char *name,
    uint32_t timeout_milliseconds,
    uint64_t *elapsed_nanoseconds
);

#endif
