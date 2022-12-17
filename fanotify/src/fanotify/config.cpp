#include <fanotify/config.h>
#include <nlohmann/json.hpp>
#include <iostream>

using json = nlohmann::json;

constexpr const char* g_configPath = "/etc/synthmoza/fanotify_config.json";

namespace fn
{

// Get default config (when we can't find config file)
static Config GetDefaultConfig()
{
    return Config
    {
        .fanotifyFlags = FAN_CLOEXEC | FAN_CLASS_CONTENT | FAN_NONBLOCK,
        .fanotifyEventFlags = O_RDONLY | O_LARGEFILE,
        .markFlags = {
            FAN_ACCESS, 
            FAN_ACCESS_PERM, 
            FAN_MODIFY,
            FAN_OPEN,
            FAN_OPEN_PERM,
            FAN_CLOSE,
            FAN_CLOSE_NOWRITE,
            FAN_CLOSE_WRITE,
        },
        .fileIOSuspect = {
            .reads = 300,
            .writes = 300,
        },
        .fileIOMaxAge = 150,
    #ifndef DAEMON_FANOTIFY
        .logPath = "/var/synthmoza/fanotify_trace.log",
    #else
        .logPath = "/var/log/syslog",
    #endif
        .whiteList = {}
    };
}

// Parse config that lies in g_configPath and return struct
Config GetConfig()
{
    if (!std::filesystem::exists(g_configPath))
        return GetDefaultConfig();
    
    std::ifstream fileStream(g_configPath);
    json data = json::parse(fileStream);

    Config cfg{};
    if (!data.contains("log_file_path"))
        throw std::runtime_error("Can't find necessary field in config: log_file_path");
    cfg.logPath = data["log_file_path"];

    if (!data.contains("event_read_suspect"))
        throw std::runtime_error("Can't find necessary field in config: event_read_suspect");
    cfg.fileIOSuspect.reads = data["event_read_suspect"];

    if (!data.contains("event_write_suspect"))
        throw std::runtime_error("Can't find necessary field in config: event_write_suspect");
    cfg.fileIOSuspect.writes = data["event_write_suspect"];

    if (!data.contains("event_lifetime_ms"))
        throw std::runtime_error("Can't find necessary field in config: event_lifetime_ms");
    cfg.fileIOMaxAge = data["event_lifetime_ms"];

    if (!data.contains("fanotify_flags"))
        throw std::runtime_error("Can't find necessary field in config: fanotify_flags");
    for (auto& flag : data["fanotify_flags"])
    {
        ssize_t currentFlag = StringToFanotifyFlag(flag);
        if (currentFlag < 0)
            throw std::runtime_error("Can't recognize flags in fanotify_flags");
        cfg.fanotifyFlags |= currentFlag;
    }

    if (!data.contains("event_flags"))
        throw std::runtime_error("Can't find necessary field in config: event_flags");
    for (auto& flag : data["event_flags"])
    {
        ssize_t currentFlag = StringToEventFlag(flag);
        if (currentFlag < 0)
            throw std::runtime_error("Can't recognize flags in event_flags");
        cfg.fanotifyEventFlags |= currentFlag;
    }

    if (!data.contains("event_track"))
        throw std::runtime_error("Can't find necessary field in config: event_track");
    
    // enabled by default
    cfg.markFlags.push_back(FAN_ACCESS);
    cfg.markFlags.push_back(FAN_ACCESS_PERM);
    cfg.markFlags.push_back(FAN_MODIFY);

    for (auto& flag : data["event_track"])
    {
        ssize_t currentFlag = StringToMarkFlag(flag);
        if (currentFlag < 0)
            throw std::runtime_error("Can't recognize flags in event_track");
        cfg.markFlags.push_back(currentFlag);
    }

    if (!data.contains("white_list"))
        throw std::runtime_error("Can't find necessary field in config: white_list");

    for (auto& path : data["white_list"])
        cfg.whiteList.push_back(path);

    return cfg;
}

// Parse config that lies in g_daemonConfigPath and return struct
Config GetDaemonConfig()
{
    if (!std::filesystem::exists(g_configPath))
        return GetDefaultConfig();
    
    std::ifstream fileStream(g_configPath);
    json data = json::parse(fileStream);

    Config cfg{};
    cfg.logPath = "/var/log/syslog";

    if (!data.contains("event_read_suspect"))
        throw std::runtime_error("Can't find necessary field in config: event_read_suspect");
    cfg.fileIOSuspect.reads = data["event_read_suspect"];

    if (!data.contains("event_write_suspect"))
        throw std::runtime_error("Can't find necessary field in config: event_write_suspect");
    cfg.fileIOSuspect.writes = data["event_write_suspect"];

    if (!data.contains("event_lifetime_ms"))
        throw std::runtime_error("Can't find necessary field in config: event_lifetime_ms");
    cfg.fileIOMaxAge = data["event_lifetime_ms"];

    if (!data.contains("fanotify_flags"))
        throw std::runtime_error("Can't find necessary field in config: fanotify_flags");
    for (auto& flag : data["fanotify_flags"])
    {
        ssize_t currentFlag = StringToFanotifyFlag(flag);
        if (currentFlag < 0)
            throw std::runtime_error("Can't recognize flags in fanotify_flags");
        cfg.fanotifyFlags |= currentFlag;
    }

    if (!data.contains("event_flags"))
        throw std::runtime_error("Can't find necessary field in config: event_flags");
    for (auto& flag : data["event_flags"])
    {
        ssize_t currentFlag = StringToEventFlag(flag);
        if (currentFlag < 0)
            throw std::runtime_error("Can't recognize flags in event_flags");
        cfg.fanotifyEventFlags |= currentFlag;
    }

    if (!data.contains("event_track"))
        throw std::runtime_error("Can't find necessary field in config: event_track");
    
    // enabled by default
    cfg.markFlags.push_back(FAN_ACCESS);
    cfg.markFlags.push_back(FAN_ACCESS_PERM);
    cfg.markFlags.push_back(FAN_MODIFY);

    for (auto& flag : data["event_track"])
    {
        ssize_t currentFlag = StringToMarkFlag(flag);
        if (currentFlag < 0)
            throw std::runtime_error("Can't recognize flags in event_track");
        cfg.markFlags.push_back(currentFlag);
    }

    if (!data.contains("white_list"))
        throw std::runtime_error("Can't find necessary field in config: white_list");

    for (auto& path : data["white_list"])
        cfg.whiteList.push_back(path);

    return cfg;
}

}
