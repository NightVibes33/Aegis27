#include "ResearchBridge.h"

#include <dlfcn.h>
#include <dispatch/dispatch.h>
#include <limits.h>
#include <mach/mach.h>
#include <sys/types.h>
#include <unistd.h>
#include <xpc/xpc.h>

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

int32_t aegis_bootstrap_probe_service(
    const char *name,
    uint32_t *port_type,
    uint32_t *send_right_refs
) {
    if (name == NULL || port_type == NULL || send_right_refs == NULL) {
        return KERN_INVALID_ARGUMENT;
    }

    *port_type = 0;
    *send_right_refs = 0;

    bootstrap_lookup_function lookup =
        (bootstrap_lookup_function)dlsym(RTLD_DEFAULT, "bootstrap_look_up");
    if (lookup == NULL) {
        return KERN_NOT_SUPPORTED;
    }

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
        mach_port_type_t type = 0;
        mach_port_urefs_t refs = 0;
        kern_return_t type_result = mach_port_type(
            mach_task_self(),
            service_port,
            &type
        );
        if (type_result == KERN_SUCCESS) {
            *port_type = (uint32_t)type;
        }

        kern_return_t refs_result = mach_port_get_refs(
            mach_task_self(),
            service_port,
            MACH_PORT_RIGHT_SEND,
            &refs
        );
        if (refs_result == KERN_SUCCESS) {
            *send_right_refs = (uint32_t)refs;
        }

        mach_port_deallocate(mach_task_self(), service_port);
    }

    mach_port_deallocate(mach_task_self(), bootstrap);
    return (int32_t)result;
}

// Return values are intentionally small and stable for the Swift model:
// 0 dictionary reply, 1 XPC error reply, 2 other reply, 3 timeout,
// 4 runtime API unavailable, 5 invalid argument/connection creation failure.
int32_t aegis_xpc_empty_dictionary_probe(
    const char *name,
    uint32_t timeout_milliseconds,
    uint64_t *elapsed_nanoseconds
) {
    if (name == NULL || elapsed_nanoseconds == NULL || timeout_milliseconds == 0) {
        return 5;
    }

    typedef xpc_connection_t (*create_function)(
        const char *, dispatch_queue_t, uint64_t
    );
    typedef void (*set_handler_function)(
        xpc_connection_t, xpc_handler_t
    );
    typedef void (*connection_action_function)(xpc_connection_t);
    typedef xpc_object_t (*dictionary_create_function)(
        const char * const *, const xpc_object_t *, size_t
    );
    typedef void (*send_reply_function)(
        xpc_connection_t, xpc_object_t, dispatch_queue_t, xpc_handler_t
    );
    typedef xpc_type_t (*get_type_function)(xpc_object_t);
    typedef void (*release_function)(xpc_object_t);

    create_function create_connection =
        (create_function)dlsym(RTLD_DEFAULT, "xpc_connection_create_mach_service");
    set_handler_function set_handler =
        (set_handler_function)dlsym(RTLD_DEFAULT, "xpc_connection_set_event_handler");
    connection_action_function resume_connection =
        (connection_action_function)dlsym(RTLD_DEFAULT, "xpc_connection_resume");
    connection_action_function cancel_connection =
        (connection_action_function)dlsym(RTLD_DEFAULT, "xpc_connection_cancel");
    dictionary_create_function create_dictionary =
        (dictionary_create_function)dlsym(RTLD_DEFAULT, "xpc_dictionary_create");
    send_reply_function send_with_reply =
        (send_reply_function)dlsym(RTLD_DEFAULT, "xpc_connection_send_message_with_reply");
    get_type_function get_type =
        (get_type_function)dlsym(RTLD_DEFAULT, "xpc_get_type");
    release_function release_object =
        (release_function)dlsym(RTLD_DEFAULT, "xpc_release");

    if (create_connection == NULL || set_handler == NULL ||
        resume_connection == NULL || cancel_connection == NULL ||
        create_dictionary == NULL || send_with_reply == NULL ||
        get_type == NULL) {
        return 4;
    }

    dispatch_queue_t queue = dispatch_get_global_queue(QOS_CLASS_UTILITY, 0);
    xpc_connection_t connection = create_connection(name, queue, 0);
    if (connection == NULL) {
        return 5;
    }

    set_handler(connection, ^(xpc_object_t event) {
        (void)event;
    });
    resume_connection(connection);

    xpc_object_t message = create_dictionary(NULL, NULL, 0);
    if (message == NULL) {
        cancel_connection(connection);
        if (release_object != NULL) {
            release_object(connection);
        }
        return 5;
    }

    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    __block int32_t disposition = 2;
    uint64_t started = dispatch_time(DISPATCH_TIME_NOW, 0);

    send_with_reply(connection, message, queue, ^(xpc_object_t reply) {
        xpc_type_t type = reply == NULL ? NULL : get_type(reply);
        if (type == XPC_TYPE_DICTIONARY) {
            disposition = 0;
        } else if (type == XPC_TYPE_ERROR) {
            disposition = 1;
        } else {
            disposition = 2;
        }
        dispatch_semaphore_signal(semaphore);
    });

    dispatch_time_t deadline = dispatch_time(
        DISPATCH_TIME_NOW,
        (int64_t)timeout_milliseconds * (int64_t)NSEC_PER_MSEC
    );
    if (dispatch_semaphore_wait(semaphore, deadline) != 0) {
        disposition = 3;
    }

    *elapsed_nanoseconds = dispatch_time(DISPATCH_TIME_NOW, 0) - started;
    cancel_connection(connection);
    if (release_object != NULL) {
        release_object(message);
        release_object(connection);
    }
    return disposition;
}
