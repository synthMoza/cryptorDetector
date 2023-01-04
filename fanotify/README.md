# Detector overview
This program might be called a childish antivirus - it only protects against encryptors and should be configured carefuly. It uses *fanotify* to catch system calls to filesystem and tracks statistics on all processes that interact with filesystem. If it is considered suspicious, it is being killed. *Metric for suspicious* is maximum amount of reads and writes for given amount of time, that can be customised in config.Also it has *whitelist* for all programs that should not be considered encryptors (for example, */usr/bin/git* performs a lot of reads and writes in short period of time, but it is not an encryptor).

# Build project
Project is built via CMake, so the procedure is pretty standard:
```
mkdir build
cd build
cmake ..
cmake --build .
```

It generetaes several executables:
1) *encrypt* - test program to emulate cryptor (like Petya or some other virus) to be detected by detector. Can be launched using:
```
./encrypt <file-or-directory>
```
It encrypts given file or directory recursively with hard-coded key.

2) *fanotify* - detector program that uses fanotify to track suspicious proccesses. Can be launched as follows:
```
sudo ./fanotify <mount-point>
```
It will track events specified in config and kill suspicious programs (that look like cryptors) besides the one in white list.

3) *fanotify_daemon* - same program, but this one is a daemon. Writes all logs to */var/log/syslog*. Can be lacunhed like the *fanotify* program:
```
sudo ./fanotify_daemon <mount_point>
```

# Config
Config is used to set up program settings. Default config is used whent there is no in */etc/synthmoza/fanotify_config.json*, you can find example config file in the source directory, modify and copy it to the */etc/synthmoza/fanotify_config.json*. Fields with their default values are as follows:

1) ```"log_file_path": "/etc/synthmoza/fanotify.log"``` - path to the log file where program will trace events depending on the build type. In release it will only report suspicious pids,  in debug it will additionally report each event it catches and more debug info.
This field is ignored in daemon, at it should write only to */var/log/syslog*.

2) ```"event_read_suspect": 300``` - amount of reads event must have to be defined as suspicious
3) ```"event_write_suspect": 300``` - amount of writes event must have to be defined as suspicious
4) ```"event_lifetime_ms": 150``` - event timeout after which it is being deleted from the tracking system
5) ```"fanotify_flags"``` - flags that will be passed to ```fanotify_init``` function (see ```man fanotify_init```)
```
"fanotify_flags": [
        "FAN_CLOEXEC",
        "FAN_CLASS_CONTENT",
        "FAN_NONBLOCK"
    ],
```
6) ```"event_flags"``` - event flags that will be passed to ```fanotify_init``` function (see ```man fanotify_init```)
```
"event_flags": [
        "O_RDONLY",
        "O_LARGEFILE"
    ],
```
7) ```"event_track"``` - events that fanotify will track. Read and write events are enabled by default as program uses them as metrics for finding cryptors.
```
"event_track": [
        "FAN_OPEN",
        "FAN_OPEN_PERM",
        "FAN_CLOSE",
        "FAN_CLOSE_NOWRITE",
        "FAN_CLOSE_WRITE"
    ],
```

# To Do
* Save opened files to SQLite3 database to restore them after encryption
* Implement blacklist for already detected binaries not to be launched again (using SQLite3 databse or in-program data structure)
* Modify whitelist - remove it from config and allow only trusted application to modify it (for example, sqlite3 binary)
* Apply same whitelist/blacklist rules for children process and parents (except init)