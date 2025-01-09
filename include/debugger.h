#pragma once

#include "debuggee.h"

typedef enum { DETACHED = 1, ATTACHED = 2 } debugger_state;

typedef struct debugger {
        debuggee dbgee;           /**< Debuggee that is debugged by this debugger */
        debugger_state state;     /**< Current state of the debugger process */
        unsigned int catch_flags; /**< Flags used to catch specific debugging events */
} debugger;

typedef enum {
    CATCH_FORK,
    CATCH_EXEC,
    CATCH_THREAD
} catch_event_t;

void init_debugger(debugger *dbg, const char *debuggee_name);
void free_debugger(debugger *dbg);

int start_debuggee(debugger *dbg);
int trace_debuggee(debugger *dbg);
void update_ptrace_options(debugger *dbg);
