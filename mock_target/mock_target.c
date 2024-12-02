#include <stdio.h>
#include <unistd.h>

int main() {
    printf("Mock target started with PID %d\n", getpid());
    int i = 3;
    while (i >= 0) {
        sleep(1);
        i--;
    }
    return 0;
}
