#pragma once

#include "debugger.h"

typedef enum {
        CLI_EXIT,
        CLI_HELP,
        DBG_RUN,
        DBG_CONTINUE,
        DBG_REGISTERS,
        DBG_BREAK,
        DBG_HBREAK,
        DBG_LIST_BREAKPOINTS,
        DBG_REMOVE_BREAKPOINT,
        DBG_DUMP,
        DBG_DIS,
        DBG_STEP,
        DBG_STEP_OVER,
        DBG_STEP_OUT,
        DBG_RESTART,
        UNKNOWN
} command_t;

typedef struct {
        const char *command;
        command_t type;
} command_mapping;

command_t get_command_type(const char *command);

int read_and_handle_user_command(debugger *dbg);
int handle_user_input(debugger *dbg, command_t cmd_type, const char *arg);
