#include "ResearchBridge.h"

#include <dlfcn.h>
#include <dispatch/dispatch.h>
#include <limits.h>
#include <mach/mach.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
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
static uint64_t elapsed_nanoseconds(
    struct timespec started,
    struct timespec finished
) {
    uint64_t seconds = (uint64_t)(finished.tv_sec - started.tv_sec);
    int64_t nanoseconds = finished.tv_nsec - started.tv_nsec;
    if (nanoseconds < 0) {
        seconds -= 1;
        nanoseconds += NSEC_PER_SEC;
    }
    return seconds * NSEC_PER_SEC + (uint64_t)nanoseconds;
}

static uint64_t hash_key(const char *key) {
    uint64_t hash = 1469598103934665603ULL;
    for (const unsigned char *cursor = (const unsigned char *)key;
         *cursor != 0; cursor++) {
        hash ^= (uint64_t)*cursor;
        hash *= 1099511628211ULL;
    }
    return hash;
}

int32_t aegis_xpc_dictionary_probe(
    const char *name,
    const char *field_specification,
    uint32_t timeout_milliseconds,
    uint64_t *elapsed_output,
    uint32_t *reply_key_count,
    uint64_t *reply_key_hash
) {
    if (name == NULL || elapsed_output == NULL || reply_key_count == NULL ||
        reply_key_hash == NULL || timeout_milliseconds == 0) {
        return 5;
    }

    *elapsed_output = 0;
    *reply_key_count = 0;
    *reply_key_hash = 0;

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
    typedef void (*set_string_function)(xpc_object_t, const char *, const char *);
    typedef void (*set_uint64_function)(xpc_object_t, const char *, uint64_t);
    typedef void (*set_bool_function)(xpc_object_t, const char *, bool);
    typedef bool (*apply_function)(
        xpc_object_t,
        bool (^)(const char *, xpc_object_t)
    );
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
    set_string_function set_string =
        (set_string_function)dlsym(RTLD_DEFAULT, "xpc_dictionary_set_string");
    set_uint64_function set_uint64 =
        (set_uint64_function)dlsym(RTLD_DEFAULT, "xpc_dictionary_set_uint64");
    set_bool_function set_bool =
        (set_bool_function)dlsym(RTLD_DEFAULT, "xpc_dictionary_set_bool");
    apply_function apply_dictionary =
        (apply_function)dlsym(RTLD_DEFAULT, "xpc_dictionary_apply");
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

    // Each sanitized line is s:key=value, u:key=value, or b:key=0|1.
    // The importer forbids newlines/NULs in keys and values and caps this at
    // eight fields. Parsing again here keeps the C bridge fail-closed.
    if (field_specification != NULL && field_specification[0] != '\0') {
        if (set_string == NULL || set_uint64 == NULL || set_bool == NULL) {
            cancel_connection(connection);
            if (release_object != NULL) {
                release_object(message);
                release_object(connection);
            }
            return 4;
        }
        char *copy = strdup(field_specification);
        if (copy == NULL) {
            cancel_connection(connection);
            return 5;
        }
        char *save = NULL;
        char *line = strtok_r(copy, "\n", &save);
        uint32_t field_count = 0;
        bool valid = true;
        while (line != NULL && field_count < 8) {
            if (strlen(line) < 4 || line[1] != ':') {
                valid = false;
                break;
            }
            char *key = line + 2;
            char *separator = strchr(key, '=');
            if (separator == NULL || separator == key) {
                valid = false;
                break;
            }
            *separator = '\0';
            const char *value = separator + 1;
            switch (line[0]) {
            case 's': set_string(message, key, value); break;
            case 'u': set_uint64(message, key, strtoull(value, NULL, 10)); break;
            case 'b': set_bool(message, key, strcmp(value, "1") == 0); break;
            default: valid = false; break;
            }
            if (!valid) { break; }
            field_count += 1;
            line = strtok_r(NULL, "\n", &save);
        }
        if (line != NULL) { valid = false; }
        free(copy);
        if (!valid) {
            cancel_connection(connection);
            if (release_object != NULL) {
                release_object(message);
                release_object(connection);
            }
            return 5;
        }
    }

    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    __block int32_t disposition = 2;
    __block uint32_t observed_key_count = 0;
    __block uint64_t observed_key_hash = 0;
    struct timespec started;
    clock_gettime(CLOCK_MONOTONIC_RAW, &started);

    send_with_reply(connection, message, queue, ^(xpc_object_t reply) {
        xpc_type_t type = reply == NULL ? NULL : get_type(reply);
        if (type == XPC_TYPE_DICTIONARY) {
            disposition = 0;
            if (apply_dictionary != NULL) {
                apply_dictionary(reply, ^bool(const char *key, xpc_object_t value) {
                    (void)value;
                    observed_key_count += 1;
                    // XOR makes the fingerprint independent of dictionary order.
                    observed_key_hash ^= hash_key(key);
                    return observed_key_count < 256;
                });
            }
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

    struct timespec finished;
    clock_gettime(CLOCK_MONOTONIC_RAW, &finished);
    *elapsed_output = elapsed_nanoseconds(started, finished);
    *reply_key_count = observed_key_count;
    *reply_key_hash = observed_key_hash;
    cancel_connection(connection);
    if (release_object != NULL) {
        release_object(message);
        release_object(connection);
    }
    return disposition;
}

int32_t aegis_xpc_empty_dictionary_probe(
    const char *name,
    uint32_t timeout_milliseconds,
    uint64_t *elapsed_output
) {
    uint32_t key_count = 0;
    uint64_t key_hash = 0;
    return aegis_xpc_dictionary_probe(
        name,
        NULL,
        timeout_milliseconds,
        elapsed_output,
        &key_count,
        &key_hash
    );
}

int32_t aegis_iokit_open_probe(
    const char *class_name,
    uint32_t *matched,
    int32_t *open_result
) {
    if (class_name == NULL || matched == NULL || open_result == NULL) {
        return 5;
    }
    *matched = 0;
    *open_result = KERN_NOT_SUPPORTED;

    typedef void *(*matching_function)(const char *);
    typedef uint32_t (*get_service_function)(mach_port_t, void *);
    typedef kern_return_t (*open_function)(
        uint32_t, mach_port_t, uint32_t, uint32_t *
    );
    typedef kern_return_t (*close_function)(uint32_t);
    typedef kern_return_t (*release_io_function)(uint32_t);

    void *framework = dlopen(
        "/System/Library/Frameworks/IOKit.framework/IOKit",
        RTLD_LAZY | RTLD_LOCAL
    );
    if (framework == NULL) { return 4; }

    matching_function make_matching =
        (matching_function)dlsym(framework, "IOServiceMatching");
    get_service_function get_service =
        (get_service_function)dlsym(framework, "IOServiceGetMatchingService");
    open_function open_service =
        (open_function)dlsym(framework, "IOServiceOpen");
    close_function close_service =
        (close_function)dlsym(framework, "IOServiceClose");
    release_io_function release_service =
        (release_io_function)dlsym(framework, "IOObjectRelease");

    if (make_matching == NULL || get_service == NULL || open_service == NULL ||
        close_service == NULL || release_service == NULL) {
        dlclose(framework);
        return 4;
    }

    void *matching = make_matching(class_name);
    if (matching == NULL) {
        dlclose(framework);
        return 0;
    }
    uint32_t service = get_service(MACH_PORT_NULL, matching);
    if (service == 0) {
        dlclose(framework);
        return 0;
    }
    *matched = 1;

    uint32_t connection = 0;
    kern_return_t result = open_service(
        service,
        mach_task_self(),
        0,
        &connection
    );
    *open_result = (int32_t)result;
    if (result == KERN_SUCCESS && connection != 0) {
        close_service(connection);
    }
    release_service(service);
    dlclose(framework);
    return 0;
}
