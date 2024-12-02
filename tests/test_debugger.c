#include "debugger.h"

#include <criterion/criterion.h>
#include <criterion/redirect.h>

#include "test_macros.h"

#ifndef MOCK_TARGET_PATH
#define MOCK_TARGET_PATH "../bin/mock_target"
#endif

// Function to initialize a debugger instance for testing
static void init_debugger(debugger *dbg, const char *target_path) {
        dbg->target_pid = -1;
        dbg->target_name = target_path;
        dbg->debugger_state_flag = DEBUGGER_IDLE;
        dbg->target_state_flag = TARGET_IDLE;
}

// Redirect stdout and stderr for testing
void redirect_all_stdout(void) {
        cr_redirect_stdout();
        cr_redirect_stderr();
}

// Test case for start_target
Test(debugger, start_target_success) {
        debugger dbg;
        init_debugger(&dbg, MOCK_TARGET_PATH);

        int result = start_target(&dbg);
        cr_assert_eq(result, 0, "start_target failed with return value %d",
                     result);

        cr_assert_neq(dbg.target_pid, -1, "Target PID was not set.");
        cr_assert_eq(dbg.target_state_flag, TARGET_RUNNING,
                     "Target state flag not set to RUNNING.");

        free_dbg(&dbg);
}

// Test case for trace_target
Test(debugger, trace_target_success, .init = redirect_all_stdout) {
        debugger dbg;
        init_debugger(&dbg, MOCK_TARGET_PATH);

        int start_result = start_target(&dbg);
        cr_assert_eq(start_result, 0,
                     "start_target failed with return value %d", start_result);

        int trace_result = trace_target(&dbg);
        cr_assert_eq(trace_result, 0,
                     "trace_target failed with return value %d", start_result);

        cr_assert_eq(
            dbg.debugger_state_flag, DEBUGGER_RUNNING,
            "Debugger state should be RUNNING after running trace_target.");
        cr_assert_eq(dbg.target_state_flag, TARGET_TERMINATED,
                     "Target state should be TERMINATED after trace_target.");

        free_dbg(&dbg);
}

// Test case for free_dbg when target is running
Test(debugger, free_dbg_kill_running_target, .init = redirect_all_stdout) {
        debugger dbg;
        init_debugger(&dbg, MOCK_TARGET_PATH);

        int start_result = start_target(&dbg);
        cr_assert_eq(start_result, 0,
                     "start_target failed with return value %d", start_result);

        free_dbg(&dbg);

        cr_assert_eq(dbg.target_pid, -1,
                     "Target PID should be reset after free_dbg.");
        cr_assert_eq(dbg.target_state_flag, TARGET_TERMINATED,
                     "Target state flag should be TERMINATED after free_dbg.");
        cr_assert_eq(dbg.debugger_state_flag, DEBUGGER_IDLE,
                     "Debugger state flag should be IDLE after free_dbg.");
}
