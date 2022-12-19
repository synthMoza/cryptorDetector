#include <fanotify/detector.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

using namespace fn;

int daemon(const char* mount)
{
    pid_t pid = 0, sid = 0;

    pid = fork(); // 1) Fork and kill parent proc => child will have Init as its parent
    if (pid < 0)
        exit(EXIT_FAILURE);
    if (pid > 0)
        exit(EXIT_SUCCESS); // exit without error
    
    // 2) create a sis for child (detach from terminal)
    sid = setsid();
    if (sid < 0)
        exit(EXIT_FAILURE);
    // 3) change working directory to root
    if (chdir("/") < 0)
        exit(EXIT_FAILURE);
    // 4) close all fd's
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // now launch the program
    Tracer tracer{};
    try
    {
        Config cfg = GetDaemonConfig();
        TRACE(tracer, "Got daemon config");
        EncryptorDetector detector(mount, cfg);
        TRACE(tracer, "Initialized detector");
        detector.Launch();
    }
    catch (const std::exception& e)
    {
        TRACE(tracer, e.what());

        exit(EXIT_FAILURE);
    }

    return 0;
}

int main()
{
    const char* mountPoint = "/";
    return daemon(mountPoint);
}
