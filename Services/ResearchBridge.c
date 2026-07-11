#include "ResearchBridge.h"

#include <dlfcn.h>
#include <limits.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <sys/types.h>
#include <unistd.h>

typedef int (*sandbox_check_function)(pid_t, const char *, int, ...);

enum {
    AEGIS_SANDBOX_FILTER_PATH = 1,
    AEGIS_SANDBOX_FILTER_GLOBAL_NAME = 2
};

static sandbox_check_function resolve_sandbox_check(void) {
    static sandbox_check_function function = NULL;
    static int attempted = 0;
    if (!attempted) {
        attempted = 1;
        function = (sandbox_check_function)dlsym(RTLD_DEFAULT, "sandbox_check");
    }
    return function;
}

int32_t aegis_sandbox_check_path(const char *operation, const char *path) {
    sandbox_check_function function = resolve_sandbox_check();
    if (function == NULL || operation == NULL || path == NULL) {
        return INT32_MIN;
    }
    return (int32_t)function(
        getpid(),
        operation,
        AEGIS_SANDBOX_FILTER_PATH,
        path
    );
}

int32_t aegis_sandbox_check_global_name(const char *operation, const char *name) {
    sandbox_check_function function = resolve_sandbox_check();
    if (function == NULL || operation == NULL || name == NULL) {
        return INT32_MIN;
    }
    return (int32_t)function(
        getpid(),
        operation,
        AEGIS_SANDBOX_FILTER_GLOBAL_NAME,
        name
    );
}

int32_t aegis_bootstrap_lookup_service(const char *name) {
    if (name == NULL) {
        return KERN_INVALID_ARGUMENT;
    }

    mach_port_t service_port = MACH_PORT_NULL;
    kern_return_t result = bootstrap_look_up(
        bootstrap_port,
        (char *)name,
        &service_port
    );

    if (result == KERN_SUCCESS && service_port != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), service_port);
    }
    return (int32_t)result;
}
