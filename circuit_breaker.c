/**
 * Circuit Breaker Implementation
 *
 * State machine: CLOSED (normal) -> OPEN (failing) -> HALF_OPEN (testing) -> CLOSED
 *
 * Based on the standard circuit breaker pattern for fault tolerance.
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_MSC_VER)
#  include "compat/pthreads/pthread.h"
#else
#  include <pthread.h>
#endif

#include "circuit_breaker.h"

circuit_breaker_t *circuit_breaker_init(const char *name,
                                         int failure_threshold,
                                         int success_threshold,
                                         int timeout_ms)
{
    circuit_breaker_t *cb = (circuit_breaker_t *)calloc(1, sizeof(circuit_breaker_t));
    if (!cb)
        return NULL;

    cb->name = strdup(name ? name : "unknown");
    if (!cb->name) {
        free(cb);
        return NULL;
    }

    cb->state = CB_STATE_CLOSED;
    cb->failure_count = 0;
    cb->success_count = 0;
    cb->failure_threshold = failure_threshold > 0 ? failure_threshold : 5;
    cb->success_threshold = success_threshold > 0 ? success_threshold : 2;
    cb->timeout_ms = timeout_ms > 0 ? timeout_ms : 30000;
    cb->last_failure_time = 0;
    cb->state_change_time = time(NULL);

    if (pthread_mutex_init(&cb->lock, NULL) != 0) {
        free(cb->name);
        free(cb);
        return NULL;
    }

    applog(LOG_DEBUG, "Circuit breaker '%s' initialized: threshold=%d, success=%d, timeout=%dms",
           cb->name, cb->failure_threshold, cb->success_threshold, cb->timeout_ms);

    return cb;
}

bool circuit_breaker_allow(circuit_breaker_t *cb)
{
    if (!cb)
        return true; /* No circuit breaker, allow */

    bool allow = false;
    time_t now = time(NULL);

    pthread_mutex_lock(&cb->lock);

    switch (cb->state) {
    case CB_STATE_CLOSED:
        allow = true;
        break;

    case CB_STATE_OPEN:
        /* Check if timeout has elapsed to transition to HALF_OPEN */
        if (now - cb->last_failure_time >= (cb->timeout_ms / 1000)) {
            cb->state = CB_STATE_HALF_OPEN;
            cb->success_count = 0;
            cb->state_change_time = now;
            applog(LOG_INFO, "Circuit breaker '%s': OPEN -> HALF_OPEN (timeout elapsed)",
                   cb->name);
            allow = true;
        } else {
            allow = false;
        }
        break;

    case CB_STATE_HALF_OPEN:
        /* Allow one request to test the waters */
        allow = true;
        break;
    }

    pthread_mutex_unlock(&cb->lock);
    return allow;
}

void circuit_breaker_record_result(circuit_breaker_t *cb, bool success)
{
    if (!cb)
        return;

    time_t now = time(NULL);

    pthread_mutex_lock(&cb->lock);

    switch (cb->state) {
    case CB_STATE_CLOSED:
        if (success) {
            cb->failure_count = 0;
        } else {
            cb->failure_count++;
            cb->last_failure_time = now;
            if (cb->failure_count >= cb->failure_threshold) {
                cb->state = CB_STATE_OPEN;
                cb->state_change_time = now;
                applog(LOG_WARNING, "Circuit breaker '%s': CLOSED -> OPEN (failures=%d)",
                       cb->name, cb->failure_count);
            }
        }
        break;

    case CB_STATE_OPEN:
        /* Should not happen since allow() returns false in OPEN state,
         * but handle gracefully */
        if (success) {
            cb->state = CB_STATE_HALF_OPEN;
            cb->success_count = 1;
            cb->state_change_time = now;
            applog(LOG_INFO, "Circuit breaker '%s': OPEN -> HALF_OPEN (success recorded)",
                   cb->name);
        }
        break;

    case CB_STATE_HALF_OPEN:
        if (success) {
            cb->success_count++;
            if (cb->success_count >= cb->success_threshold) {
                cb->state = CB_STATE_CLOSED;
                cb->failure_count = 0;
                cb->success_count = 0;
                cb->state_change_time = now;
                applog(LOG_INFO, "Circuit breaker '%s': HALF_OPEN -> CLOSED (successes=%d)",
                       cb->name, cb->success_count);
            }
        } else {
            cb->state = CB_STATE_OPEN;
            cb->failure_count = 1;
            cb->last_failure_time = now;
            cb->state_change_time = now;
            applog(LOG_WARNING, "Circuit breaker '%s': HALF_OPEN -> OPEN (test failed)",
                   cb->name);
        }
        break;
    }

    pthread_mutex_unlock(&cb->lock);
}

const char *circuit_breaker_state_str(circuit_breaker_t *cb)
{
    if (!cb)
        return "none";

    switch (cb->state) {
    case CB_STATE_CLOSED:
        return "closed";
    case CB_STATE_OPEN:
        return "open";
    case CB_STATE_HALF_OPEN:
        return "half_open";
    default:
        return "unknown";
    }
}

void circuit_breaker_free(circuit_breaker_t *cb)
{
    if (!cb)
        return;

    pthread_mutex_destroy(&cb->lock);
    free(cb->name);
    free(cb);
}