#include "debugger.h"
#include "macros.h"

#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

bool file_exists(const char *filename);

int main(int argc, char **argv) {
        if (argc < 2) {
                FATAL("Usage: %s <debug_target>\n", argv[0]);
        }

        const char *target_name = argv[1];

        if (!file_exists(target_name)) {
                FATAL("Cannot find executable %s", target_name);
        }

        debugger dbg = {
            .target_pid = -1,
            .target_name = target_name,
            .debugger_state_flag = DEBUGGER_IDLE,
            .target_state_flag = TARGET_IDLE,
        };

        if (start_dbg(&dbg) != 0) {
                free_dbg(&dbg);
                return EXIT_FAILURE;
        }

        free_dbg(&dbg);

        return EXIT_SUCCESS;
}

bool file_exists(const char *filename) { return access(filename, F_OK) == 0; }
