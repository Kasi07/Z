#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "debugger.h"
#include "macros.h"

int start_dbg(debugger *dbg) {
        printf("Starting debugger.\n");
        dbg->debugger_state_flag = DEBUGGER_RUNNING;

        if (start_target(dbg) != 0) {
                FATAL("Failed to start target: %s", dbg->target_name);
                free_dbg(dbg);
                return EXIT_FAILURE;
        }

        if (trace_target(dbg) != 0) {
                FATAL("Failed to trace target: %s", dbg->target_name);
                free_dbg(dbg);
                return EXIT_FAILURE;
        }

        printf("Finished tracing target.\n");
        return EXIT_SUCCESS;
}

void free_dbg(debugger *dbg) {
        if (dbg->debugger_state_flag == DEBUGGER_ATTACHED) {
                if (ptrace(PTRACE_DETACH, dbg->target_pid, NULL, NULL) == -1) {
                        (void)(fprintf(
                            stderr,
                            "Failed to detach from child with PID %d: %s\n",
                            dbg->target_pid, strerror(errno)));
                } else {
                        printf("Detached from child with PID: %d\n",
                               dbg->target_pid);
                }
        }

        if ((dbg->target_state_flag == TARGET_RUNNING) ||
            (dbg->target_state_flag == TARGET_STOPPED)) {
                if (kill(dbg->target_pid, SIGKILL) == -1) {
                        (void)(fprintf(stderr,
                                       "Failed to kill child with PID %d: %s\n",
                                       dbg->target_pid, strerror(errno)));
                } else {
                        printf("Killed child with PID: %d\nExiting...\n",
                               dbg->target_pid);
                }
        } else if (dbg->target_state_flag == TARGET_TERMINATED) {
                printf("Child with PID %d has already terminated.\n",
                       dbg->target_pid);
        }

        dbg->target_pid = -1;
        dbg->debugger_state_flag = DEBUGGER_IDLE;
        dbg->target_state_flag = TARGET_TERMINATED;
}

/*
 * Sets target_pid
 *      -> Success: Child pid
 *      -> Failure: -1
 * Sets target_state_flag
 *      -> Success: TARGET_RUNNING
 *      -> Failure: TARGET_TERMINATED
 */
int start_target(debugger *dbg) {
        pid_t pid = fork();
        if (pid == -1) {
                perror("fork");
                return -1;
        }

        if (pid == 0) { // Child process
                if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
                        perror("ptrace");
                        exit(EXIT_FAILURE);
                }
                execl(dbg->target_name, dbg->target_name, NULL);
                perror("execl");
                exit(EXIT_FAILURE);
        } else { // Parent process
                dbg->target_pid = pid;
                dbg->target_state_flag = TARGET_RUNNING;

                int status;
                if (waitpid(dbg->target_pid, &status, 0) == -1) {
                        perror("waitpid");
                        dbg->target_pid = -1;
                        dbg->target_state_flag = TARGET_TERMINATED;
                        return EXIT_FAILURE;
                }

                if (WIFEXITED(status)) {
                        (void)(fprintf(
                            stderr,
                            "Child process exited prematurely with status %d\n",
                            WEXITSTATUS(status)));
                        dbg->target_pid = -1;
                        dbg->target_state_flag = TARGET_TERMINATED;
                        return EXIT_FAILURE;
                }

                if (ptrace(PTRACE_SETOPTIONS, dbg->target_pid, 0,
                           PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD) == -1) {
                        perror("ptrace SETOPTIONS");
                        dbg->target_pid = -1;
                        dbg->target_state_flag = TARGET_TERMINATED;
                        return EXIT_FAILURE;
                }

                // In the future we might not want to continue here
                if (ptrace(PTRACE_CONT, dbg->target_pid, NULL, NULL) == -1) {
                        perror("ptrace CONT after SETOPTIONS");
                        dbg->target_pid = -1;
                        dbg->target_state_flag = TARGET_TERMINATED;
                        return EXIT_FAILURE;
                }

                printf("Child process started with PID %d\n", dbg->target_pid);
        }

        return EXIT_SUCCESS;
}

/*
 * Sets debugger_state_flag
 *      -> Default:            DEBUGGER_ATTACHED
 *      -> Target-Termination: DEBUGGER_RUNNING
 * Sets target_state_flag
 *      -> Termination: TARGET_TERMINATED
 *      -> Stopsignal:  TARGET_STOPPED
 *      -> Continue:    TARGET_RUNNING
 */
int trace_target(debugger *dbg) {
        printf("Entering trace_target.\n");
        dbg->debugger_state_flag = DEBUGGER_ATTACHED;

        while (dbg->debugger_state_flag == DEBUGGER_ATTACHED) {
                int status;
                pid_t pid = waitpid(dbg->target_pid, &status, 0);
                if (pid == -1) {
                        if (errno == EINTR) {
                                continue; // Interrupted by signal, retry
                        }
                        perror("waitpid");
                        return EXIT_FAILURE;
                }

                if (WIFEXITED(status)) {
                        printf("Child %d exited with status %d.\n", pid,
                               WEXITSTATUS(status));
                        dbg->debugger_state_flag = DEBUGGER_RUNNING;
                        dbg->target_state_flag = TARGET_TERMINATED;
                        break;
                }

                if (WIFSIGNALED(status)) {
                        printf("Child %d was killed by signal %d.\n", pid,
                               WTERMSIG(status));
                        dbg->debugger_state_flag = DEBUGGER_RUNNING;
                        dbg->target_state_flag = TARGET_TERMINATED;
                        break;
                }

                if (WIFSTOPPED(status)) {
                        int sig = WSTOPSIG(status);
                        printf("Child %d stopped by signal %d.\n", pid, sig);
                        dbg->target_state_flag = TARGET_STOPPED;

                        // TODO: Handle specific signals if needed
                        // For example, handle breakpoints or single-stepping

                        // Continue the child process
                        if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
                                perror("ptrace CONT");
                                return -1;
                        }

                        printf("Continued child process %d.\n", pid);
                        dbg->target_state_flag = TARGET_RUNNING;
                }

                // TODO: Implement a mechanism to break the loop, such as
                // listening for user input to stop debugging
        }

        return EXIT_SUCCESS;
}
