#include <fanotify/detector.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

using namespace fn;

constexpr const char* pidFilePath = "/run/fanotify_daemon.pid";
static Tracer g_tracer{};

static int CreatePidFile()
{
    int fd = open(pidFilePath, O_RDWR|O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd < 0) 
    {
        TRACE(g_tracer, "Failed to open pid file");
        return -1;
    }
    
    if (ftruncate(fd, 0) < 0)
    {
        TRACE(g_tracer, "Can't truncate pid file");
        return -1;
    }

    const size_t bufferSize = 16;
    char buffer[bufferSize] = {};
    sprintf(buffer, "%ld", (long) getpid());
    
    ssize_t toWrite = strlen(buffer) + 1;
    if (write(fd, buffer, toWrite) != toWrite)
    {
        TRACE(g_tracer, "Can't write to pid file");
        return -1;
    }
    
    close(fd);

    return 0;
}

int daemon_setup()
{
    pid_t pid = 0, sid = 0;

    pid = fork(); // 1) Fork and kill parent proc => child will have Init as its parent
    if (pid < 0)
    {
        TRACE(g_tracer, "Can't fork process");
        return EXIT_FAILURE;
    }
    if (pid > 0)
        exit(0); // exit without error
    
    // 2) create a sis for child (detach from terminal)
    sid = setsid();
    if (sid < 0)
    {
        TRACE(g_tracer, "Failed call of setsid function");
        return EXIT_FAILURE;
    }

    /* Save parent pid */
    pid_t ppid = getpid();

    /* Fork off for the second time*/
    pid = fork();

    /* An error occurred */
    if (pid < 0) {
        syslog(LOG_ERR, "fork failed: %s", strerror(errno));
        return errno;
    }

    /* Success: Let the parent terminate */
    if (pid > 0)
        exit(0);

    umask(0);

    // 3) change working directory to root
    if (chdir("/") < 0)
    {
        TRACE(g_tracer, "Failed call of chdir function");
        return EXIT_FAILURE;
    }
    // 4) close all fd's
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    /* Reopen stdin (fd = 0), stdout (fd = 1), stderr (fd = 2) */
    int fd0 = open("/dev/null", O_RDWR);
    /* 'fd0' should be 0 */
    if (fd0 != STDIN_FILENO) {
        syslog(LOG_ERR, "fd0(%d) is not equal STDIN_FILENO(%d)", fd0, STDIN_FILENO);
        return -1;
    }

    int fd1 = dup(0);
    /* 'fd1' should be 1 */
    if (fd1 != STDOUT_FILENO) {
        syslog(LOG_ERR, "fd1(%d) is not equal STDOUT_FILENO(%d)", fd1, STDOUT_FILENO);
        return -1;
    }

    int fd2 = dup(0);
    /* 'fd2' should be 2 */
    if (fd2 != STDERR_FILENO) {
        syslog(LOG_ERR, "fd2(%d) is not equal STDERR_FILENO(%d)", fd2, STDERR_FILENO);
        return -1;
    }

    /* Waitting 1 minute while parent does not exit,
    * because systemd using pid_file check who our parent.
    * And in same cases it stop our daemon using SIGKILL. */
   const long long TIMEOUT_MS = 60000 ; // 1 minute
    const long long RETRY_TIME_MS = 20;
    const long long N_RETRY = TIMEOUT_MS / RETRY_TIME_MS;
    struct timespec req = {};
    for (long i = 0; i < N_RETRY && getppid() == ppid; ++i) {
            req.tv_sec = 0;
            req.tv_nsec = RETRY_TIME_MS * 1000 * 1000;
            nanosleep(&req, NULL);
    }

    for (int fd = sysconf(_SC_OPEN_MAX); fd >= 0; fd--)
        close(fd);

    // 5) create pid file for systemd
    if (CreatePidFile() < 0) 
    {
        TRACE(g_tracer, "Fanotify daemon is already running");
        return -1;
    }

    return 0;
}

int main()
{
    int res = daemon_setup();
    if (res < 0)
        return res;

    Tracer tracer{};
    try
    {
        Config cfg = GetDaemonConfig();
        TRACE(tracer, "Got daemon config");
        EncryptorDetector detector("/", cfg);
        TRACE(tracer, "Initialized detector");
        detector.Launch();
    }
    catch (const std::exception& e)
    {
        TRACE(tracer, e.what());

        return EXIT_FAILURE;
    }
}
