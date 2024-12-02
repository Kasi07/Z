#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

typedef enum {
        TARGET_IDLE = 0,
        TARGET_STOPPED = 1,
        TARGET_RUNNING = 2,
        TARGET_TERMINATED = 3
} target_state;

typedef enum {
        DEBUGGER_IDLE = 0,
        DEBUGGER_RUNNING = 1,
        DEBUGGER_ATTACHED = 2
} debugger_state;

typedef struct debugger {
        pid_t target_pid;        /**< Process ID of the target being debugged */
        const char *target_name; /**< Name or path of the target executable */
        debugger_state
            debugger_state_flag; /**< Current state of the debugger process */
        target_state
            target_state_flag; /**< Current state of the target process */
} debugger;

int start_dbg(debugger *dbg);
void free_dbg(debugger *dbg);

int start_target(debugger *dbg);
int trace_target(debugger *dbg);
