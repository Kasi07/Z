#pragma once

typedef enum {
        SOFTWARE_BP,
        HARDWARE_BP,
} breakpoint_type;

typedef struct software_breakpoint {
        unsigned int id;
        void *address;
} software_breakpoint;

typedef struct hardware_breakpoint {
        unsigned int id;
        void *address;
        int condition;
} hardware_breakpoint;

typedef union {
        software_breakpoint sw;
        hardware_breakpoint hw;
} breakpoint_data;

typedef struct breakpoint {
        breakpoint_type type;
        breakpoint_data data;
        struct breakpoint *next;
} breakpoint;

typedef struct breakpoint_handler {
        breakpoint *head;
        unsigned int next_id;
} breakpoint_handler;

breakpoint_handler *create_breakpoint_handler(void);
void free_breakpoint_handler(breakpoint_handler *bp_handler);

int add_breakpoint(breakpoint_handler *bp_handler, breakpoint_type type,
                   void *address, int condition);
int remove_breakpoint(breakpoint_handler *bp_handler, unsigned int id);
int list_breakpoints(breakpoint_handler *bp_handler);
