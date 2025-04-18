# SysView - Linux Syscall Monitoring Tool

SysView is a powerful, curses-based Linux system call monitoring utility that provides real-time visualization of syscall activity on your system. It allows you to observe, track, and analyze which system calls are being made and at what rate, helping you understand application behavior, diagnose performance issues, and detect abnormal system activity.

## Features

- Real-time monitoring of Linux system calls
- Customizable visualization with color-coded syscall categories
- Graphical histograms showing syscall rate trends over time
- Comprehensive summary view with totals, averages, and peak rates
- JSON configuration for customizing which syscalls to monitor
- Output results to JSON for further analysis
- Support for syscall aliases to group related calls (e.g., poll/select/epoll)
- Categorized syscalls (file operations, memory management, network, etc.)

## Requirements

- Linux kernel (with BPF support)
- Python 3.6+
- BCC (BPF Compiler Collection)
- curses library

## Installation

1. Install dependencies:

```bash
# Debian/Ubuntu
sudo apt-get install python3-bpfcc bpfcc-tools linux-headers-$(uname -r)

# Fedora
sudo dnf install bcc-tools kernel-devel

# Arch Linux
sudo pacman -S bcc python-bcc
```

2. Clone this repository:

```bash
git clone https://github.com/yourusername/sysview.git
cd sysview
```

3. Make the script executable:

```bash
chmod +x sysview.py
```

## Usage

Basic usage:

```bash
sudo ./sysview.py
```

> Note: Root permissions are required to access kernel tracing capabilities.

### Command Line Options

```
usage: sysview.py [-h] [--config CONFIG] [--interval INTERVAL] [--history HISTORY] [--output OUTPUT] [--generate-config GENERATE_CONFIG]

Extensible Syscall Monitoring Tool

optional arguments:
  -h, --help            show this help message and exit
  --config CONFIG, -c CONFIG
                        Configuration file (JSON)
  --interval INTERVAL, -i INTERVAL
                        Sampling interval in seconds
  --history HISTORY, -H HISTORY
                        History size (number of samples to display)
  --output OUTPUT, -o OUTPUT
                        Save results to file (JSON)
  --generate-config GENERATE_CONFIG, -g GENERATE_CONFIG
                        Generate default config file and exit
```

### Configuration

SysView allows you to customize which syscalls are monitored using a JSON configuration file. You can generate a default configuration with:

```bash
sudo ./sysview.py --generate-config sysview.json
```

The configuration file structure looks like:

```json
{
  "syscalls": {
    "read": {
      "name": "read",
      "color": 1,
      "color_def": 1,
      "desc": "Read from a file descriptor (file)",
      "enabled": true,
      "category": "file"
    },
    ...
  },
  "categories": {
    "file": "File Operations",
    "memory": "Memory Management",
    "process": "Process Control",
    "network": "Network Operations",
    "ipc": "Inter-Process Communication",
    "time": "Time Functions",
    "other": "Miscellaneous Syscalls"
  }
}
```

You can:
- Enable/disable specific syscalls
- Customize colors and descriptions
- Add new syscalls to monitor
- Define aliases for related syscalls (e.g., different polling mechanisms)

### Interactive Interface

While running, SysView displays:

- Color-coded real-time syscall rates
- Mini-histograms showing recent activity trends
- Total counts and current rates

Press Ctrl+C to exit the live view and display the summary screen, which shows:
- Monitoring session statistics
- Ranked list of syscalls by frequency
- Percentage breakdown of syscall distribution
- Peak rates observed

## Examples

Monitor with a custom configuration and 0.5 second sampling interval:
```bash
sudo ./sysview.py --config mysyscalls.json --interval 0.5
```

Track syscalls for 10 minutes and save results:
```bash
sudo ./sysview.py --output results.json
# Press Ctrl+C after 10 minutes
```

Use smaller history for constrained terminal space:
```bash
sudo ./sysview.py --history 30
```

## Use Cases

- Profiling application behavior and resource usage
- Identifying excessive syscall patterns
- Debugging system performance issues
- Educational tool for understanding OS internals
- Security monitoring for unusual syscall patterns

## License

[MIT License](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
