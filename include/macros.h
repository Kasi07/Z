#pragma once

#include <stdio.h>
#include <stdlib.h>

#define FATAL(fmt, ...)                                                        \
        do {                                                                   \
                (void)(fprintf(stderr, "FATAL: " fmt "\n", __VA_ARGS__));      \
                exit(EXIT_FAILURE);                                            \
        } while (0)

static inline void clean_stdin(void) {
        int c;
        while ((c = getchar()) != '\n' && c != EOF) {
                // Discard characters until end of the file or EOF
        }
}
