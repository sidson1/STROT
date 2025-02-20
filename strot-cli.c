#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    // Method 1: Using system()
    int status = system("python3 strot-cli.py");
    if (status == -1) {
        perror("system call failed");
        return 1;
    }

    // Alternatively, use execvp (Method 2)
    /*
    char *args[] = {"python3", "strot.py", NULL};
    execvp(args[0], args);
    perror("execvp failed");
    return 1;
    */
    
    return 0;
}

