#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "breakpoint_handler.h"

breakpoint_handler *create_breakpoint_handler(void) {
        breakpoint_handler *handler = malloc(sizeof(breakpoint_handler));
        if (!handler) {
                perror("Failed to create breakpoint handler");
                exit(EXIT_FAILURE);
        }
        handler->head = NULL;
        handler->next_id = 1;
        return handler;
}

void free_breakpoint_handler(breakpoint_handler *handler) {
        if (!handler) {
                return;
        }

        breakpoint *current = handler->head;
        while (current) {
                breakpoint *temp = current;
                current = current->next;
                free(temp);
        }
        free(handler);
}

int add_breakpoint(breakpoint_handler *handler, breakpoint_type type,
                   void *address, int condition) {
        if (!handler || !address) {
                return EXIT_FAILURE;
        }

        breakpoint *new_bp = malloc(sizeof(breakpoint));
        if (!new_bp) {
                perror("Failed to add breakpoint");
                return EXIT_FAILURE;
        }

        new_bp->type = type;
        new_bp->next = NULL;

        new_bp->data.sw.id = handler->next_id;
        handler->next_id++;

        if (type == SOFTWARE_BP) {
                new_bp->data.sw.address = address;
                // Initialize other software breakpoint fields if necessary
        } else if (type == HARDWARE_BP) {
                new_bp->data.hw.address = address;
                new_bp->data.hw.condition = condition;
                // Initialize other hardware breakpoint fields if necessary
        }

        new_bp->next = handler->head;
        handler->head = new_bp;

        printf("Added %s breakpoint with ID %u at address %p\n",
               type == SOFTWARE_BP ? "software" : "hardware",
               new_bp->type == SOFTWARE_BP ? new_bp->data.sw.id
                                           : new_bp->data.hw.id,
               address);

        return new_bp->data.sw.id;
}

int remove_breakpoint(breakpoint_handler *handler, unsigned int id) {
        if (!handler || !handler->head) {
                return -1;
        }

        breakpoint *current = handler->head;
        breakpoint *prev = NULL;

        while (current) {
                unsigned int current_id = (current->type == SOFTWARE_BP)
                                              ? current->data.sw.id
                                              : current->data.hw.id;
                if (current_id == id) {
                        if (prev) {
                                prev->next = current->next;
                        } else {
                                handler->head = current->next;
                        }
                        free(current);
                        printf("Removed breakpoint with ID %u\n", id);
                        return EXIT_SUCCESS;
                }
                prev = current;
                current = current->next;
        }
        return EXIT_FAILURE;
}

int list_breakpoints(breakpoint_handler *handler) {
        if (!handler) {
                return EXIT_FAILURE;
        }

        breakpoint *current = handler->head;
        if (!current) {
                printf("No breakpoints set.\n");
                return EXIT_SUCCESS;
        }

        printf("Current Breakpoints:\n");
        printf("--------------------\n");
        while (current) {
                if (current->type == SOFTWARE_BP) {
                        printf("ID: %u | Type: Software | Address: %p\n",
                               current->data.sw.id, current->data.sw.address);
                } else if (current->type == HARDWARE_BP) {
                        printf("ID: %u | Type: Hardware | Address: %p "
                               "| Condition: %d\n",
                               current->data.hw.id, current->data.hw.address,
                               current->data.hw.condition);
                }
                current = current->next;
        }
        return EXIT_SUCCESS;
}
