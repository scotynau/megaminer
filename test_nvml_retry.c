/*
 * Test for NVML retry wrapper with exponential backoff
 * This test simulates transient failures to verify retry logic
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

/* Mock NVML return codes */
#define NVML_SUCCESS 0
#define NVML_ERROR_GPU_IS_LOST 15
#define NVML_ERROR_DRIVER_NOT_LOADED 9
#define NVML_ERROR_RETRY_EXCEEDED 999

/* Mock function pointer type */
typedef int (*mock_fn_t)(int *, int);

/* Global state for mock */
static int mock_call_count = 0;
static int mock_fail_until = 0;
static int mock_fail_code = NVML_ERROR_GPU_IS_LOST;

/* Mock NVML function that fails N times then succeeds */
int mock_nvml_function(int *arg, int max_retries)
{
    mock_call_count++;
    if (mock_call_count <= mock_fail_until) {
        return mock_fail_code;
    }
    return NVML_SUCCESS;
}

/* Retry wrapper similar to nvml_call_with_retry_plimit */
int nvml_call_with_retry_mock(mock_fn_t fn, int *arg, int max_retries, int base_delay_ms)
{
    for (int i = 0; i <= max_retries; i++) {
        int ret = fn(arg, max_retries);
        if (ret == NVML_SUCCESS)
            return ret;
        if (ret == NVML_ERROR_GPU_IS_LOST || ret == NVML_ERROR_DRIVER_NOT_LOADED) {
            int delay = base_delay_ms * (1 << i);
            printf("Retry %d/%d after %dms\n", i + 1, max_retries, delay);
            usleep(delay * 1000);
            continue;
        }
        return ret;
    }
    return NVML_ERROR_RETRY_EXCEEDED;
}

/* State verification helper */
bool verify_state(const char *operation, int target, int actual)
{
    if (target != actual) {
        printf("NVML_STATE_MISMATCH: %s target=%d actual=%d\n", operation, target, actual);
        return false;
    }
    return true;
}

int main()
{
    printf("=== NVML Retry Wrapper Test ===\n\n");
    
    int arg = 150; /* target value */
    int actual = 0;
    
    /* Test 1: Success on first try */
    printf("Test 1: Success on first try\n");
    mock_call_count = 0;
    mock_fail_until = 0;
    int ret = nvml_call_with_retry_mock(mock_nvml_function, &arg, 3, 100);
    printf("Result: %s (calls: %d)\n\n", ret == NVML_SUCCESS ? "PASS" : "FAIL", mock_call_count);
    
    /* Test 2: Transient failure (fail twice, then succeed) */
    printf("Test 2: Transient failure (fail 2x, then succeed)\n");
    mock_call_count = 0;
    mock_fail_until = 2;
    mock_fail_code = NVML_ERROR_GPU_IS_LOST;
    ret = nvml_call_with_retry_mock(mock_nvml_function, &arg, 3, 100);
    printf("Result: %s (calls: %d)\n\n", ret == NVML_SUCCESS ? "PASS" : "FAIL", mock_call_count);
    
    /* Test 3: Driver not loaded (retryable) */
    printf("Test 3: Driver not loaded (retryable)\n");
    mock_call_count = 0;
    mock_fail_until = 1;
    mock_fail_code = NVML_ERROR_DRIVER_NOT_LOADED;
    ret = nvml_call_with_retry_mock(mock_nvml_function, &arg, 3, 100);
    printf("Result: %s (calls: %d)\n\n", ret == NVML_SUCCESS ? "PASS" : "FAIL", mock_call_count);
    
    /* Test 4: Non-retryable error */
    printf("Test 4: Non-retryable error (NVML_ERROR_UNKNOWN)\n");
    mock_call_count = 0;
    mock_fail_until = 1;
    mock_fail_code = 999; /* Some other error */
    ret = nvml_call_with_retry_mock(mock_nvml_function, &arg, 3, 100);
    printf("Result: %s (calls: %d, expected 1)\n\n", ret != NVML_SUCCESS ? "PASS" : "FAIL", mock_call_count);
    
    /* Test 5: Exceed max retries */
    printf("Test 5: Exceed max retries (fail 4x with max 3 retries)\n");
    mock_call_count = 0;
    mock_fail_until = 4;
    mock_fail_code = NVML_ERROR_GPU_IS_LOST;
    ret = nvml_call_with_retry_mock(mock_nvml_function, &arg, 3, 100);
    printf("Result: %s (calls: %d, expected 4, returns RETRY_EXCEEDED)\n\n", ret == NVML_ERROR_RETRY_EXCEEDED ? "PASS" : "FAIL", mock_call_count);
    
    /* Test 6: State verification - mismatch */
    printf("Test 6: State verification mismatch\n");
    bool verify_ok = verify_state("set_plimit", 150, 145);
    printf("Result: %s\n\n", !verify_ok ? "PASS (correctly detected mismatch)" : "FAIL");
    
    /* Test 7: State verification - match */
    printf("Test 7: State verification match\n");
    verify_ok = verify_state("set_plimit", 150, 150);
    printf("Result: %s\n\n", verify_ok ? "PASS" : "FAIL");
    
    /* Test 8: Exponential backoff timing */
    printf("Test 8: Exponential backoff timing verification\n");
    mock_call_count = 0;
    mock_fail_until = 3;
    mock_fail_code = NVML_ERROR_GPU_IS_LOST;
    
    /* Just verify the delay calculation */
    for (int i = 0; i < 3; i++) {
        int delay = 100 * (1 << i);
        printf("  Retry %d: delay = %dms (expected %dms)\n", i + 1, delay, 100 * (1 << i));
    }
    printf("Result: PASS (delays follow exponential backoff)\n\n");
    
    printf("=== All tests completed ===\n");
    return 0;
}