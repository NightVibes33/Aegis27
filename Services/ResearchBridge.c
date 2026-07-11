#include "ResearchBridge.h"

#include <dlfcn.h>
#include <limits.h>
#include <mach/mach.h>
#include <sys/types.h>
#include <unistd.h>

typedef int (*sandbox_check_function)(pid_t, const char *, int, ...);
typedef kern_return_t (*bootstrap_lookup_function)(
    mach_port_t,
    const char *,
    mach_port_t *
);

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

    bootstrap_lookup_function lookup =
        (bootstrap_lookup_function)dlsym(RTLD_DEFAULT, "bootstrap_look_up");
    if (lookup == NULL) {
        return KERN_NOT_SUPPORTED;
    }

    // TASK_BOOTSTRAP_PORT is task special port slot 4. Obtaining our own
    // bootstrap port does not require a private SDK header.
    mach_port_t bootstrap = MACH_PORT_NULL;
    kern_return_t result = task_get_special_port(
        mach_task_self(),
        4,
        &bootstrap
    );
    if (result != KERN_SUCCESS || bootstrap == MACH_PORT_NULL) {
        return (int32_t)result;
    }

    mach_port_t service_port = MACH_PORT_NULL;
    result = lookup(bootstrap, name, &service_port);

    if (result == KERN_SUCCESS && service_port != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), service_port);
    }
    mach_port_deallocate(mach_task_self(), bootstrap);
    return (int32_t)result;
}
