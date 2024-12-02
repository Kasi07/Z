#pragma once

// During tests, redefine FATAL to not exit but to log the message
#define FATAL(fmt, ...) do {                             \
    fprintf(stderr, "FATAL: " fmt "\n", ##__VA_ARGS__);  \
} while(0)

