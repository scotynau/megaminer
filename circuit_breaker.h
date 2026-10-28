#ifndef CIRCUIT_BREAKER_H
#define CIRCUIT_BREAKER_H

#include <stdint.h>
#include <time.h>

#if defined(_MSC_VER)
#  include <stdbool.h>
#  include "compat/pthreads/pthread.h"
#else
#  include <stdbool.h>
#  include <pthread.h>
#endif

typedef enum {
    CB_STATE_CLOSED = 0,
    CB_STATE_OPEN = 1,
    CB_STATE_HALF_OPEN = 2
} cb_state_t;

typedef struct circuit_breaker {
    char *name;
    cb_state_t state;
    int failure_count;
    int success_count;
    int failure_threshold;
    int success_threshold;
    int timeout_ms;
    time_t last_failure_time;
    time_t state_change_time;
    pthread_mutex_t lock;
} circuit_breaker_t;

/**
 * Initialize a circuit breaker
 * @param name Identifier for logging
 * @param failure_threshold Number of failures before opening (default 5)
 * @param success_threshold Successes needed in half-open to close (default 2)
 * @param timeout_ms Time in ms before trying half-open (default 30000)
 * @return Pointer to circuit breaker, or NULL on failure
 */
circuit_breaker_t *circuit_breaker_init(const char *name,
                                         int failure_threshold,
                                         int success_threshold,
                                         int timeout_ms);

/**
 * Check if the circuit allows a request
 * @param cb Circuit breaker instance
 * @return true if request should proceed, false if circuit is open
 */
bool circuit_breaker_allow(circuit_breaker_t *cb);

/**
 * Record the result of a request
 * @param cb Circuit breaker instance
 * @param success true if request succeeded, false otherwise
 */
void circuit_breaker_record_result(circuit_breaker_t *cb, bool success);

/**
 * Get current circuit breaker state as string
 * @param cb Circuit breaker instance
 * @return String representation of state
 */
const char *circuit_breaker_state_str(circuit_breaker_t *cb);

/**
 * Free circuit breaker resources
 * @param cb Circuit breaker instance
 */
void circuit_breaker_free(circuit_breaker_t *cb);

#endif /* CIRCUIT_BREAKER_H */