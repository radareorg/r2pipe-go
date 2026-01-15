# R2Pipe Architecture and Platform Differences

## Overview

R2Pipe is radare2's inter-process communication mechanism that allows external programs to send commands to radare2 and receive responses. This document explains how r2pipe works across different platforms, focusing on the differences between Unix-like systems and Windows.

## Unix Implementation

### Architecture
The Unix implementation uses a fork-based approach with two separate unidirectional pipes for communication:

- **Input pipe** (`input[2]`): Used to send commands from parent to child
  - Parent writes to `input[1]`
  - Child reads from `input[0]`

- **Output pipe** (`output[2]`): Used to receive responses from child to parent
  - Child writes to `output[1]`
  - Parent reads from `output[0]`

### Process Creation
1. Parent creates two pipes using `pipe()`
2. Parent calls `fork()` to create child process
3. Child redirects stdin/stdout to appropriate pipe ends
4. Child executes radare2 with the provided command
5. Parent sets environment variables `R2PIPE_IN` and `R2PIPE_OUT` for the child

### Communication Protocol
- Commands are sent as newline-terminated strings
- Responses are read until null terminator (`\x00`)
- Parent closes unused pipe ends after fork

### Native Mode (Unix only)
On Unix systems, r2pipe also supports a "native" mode that dynamically loads radare2's core library (`libr_core`) using `dlopen()` and calls functions directly:
- `r_core_new()` - Creates a new radare2 core instance
- `r_core_cmd_str()` - Executes commands and returns string responses
- `r_core_free()` - Cleans up the core instance

## Windows Implementation

### Architecture
Windows uses a single duplex named pipe for bidirectional communication:

- **Named Pipe**: `\\.\pipe\R2PIPE_IN`
  - Created with `PIPE_ACCESS_DUPLEX` for bidirectional access
  - Same handle used for both reading and writing
  - Uses message-mode pipes (`PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE`)

### Process Creation
1. Parent creates a named pipe using `CreateNamedPipe()`
2. Parent spawns child process using Windows process creation APIs
3. Child connects to the named pipe using `ConnectNamedPipe()`
4. Parent waits for child connection before proceeding

### Communication Protocol
- Commands sent using `WriteFile()` on the pipe handle
- Responses read using `ReadFile()` on the same pipe handle
- Message boundaries maintained by the pipe's message mode

### Native Mode Limitations
Windows does not support the native dlfcn-based mode because:
- No POSIX `dlfcn.h` equivalent in Windows
- Dynamic loading done via `LoadLibrary()`/`GetProcAddress()`
- Not implemented in the current Windows r2pipe code

## Go Wrapper Implementation

### Unix Version (`r2pipe_unix.go`)
- Uses `exec.Command` with separate stdin/stdout pipes
- Mimics the C implementation's fork+pipe approach
- Reads initial null byte to confirm process readiness

### Windows Version (`r2pipe_windows.go`)
- Creates named pipe with `windows.CreateNamedPipe()`
- Uses `PIPE_ACCESS_DUPLEX` for bidirectional communication
- Same pipe handle assigned to both `stdin` and `stdout` fields
- Child process inherits pipe name via `R2PIPE_IN` environment variable

### Native Version (`native.go`)
- Uses `dlfcn.h` (Unix only) to dynamically load `libr_core`
- Directly calls radare2 C API functions
- Excluded from Windows builds with `// +build !windows` constraint
- Tests also excluded with same constraint

### Build Constraints
```go
// +build !windows

// native.go and r2pipe_native_test.go
```

These constraints ensure native dlfcn functionality is only compiled on Unix-like systems.

## Key Differences

| Aspect | Unix | Windows |
|--------|------|---------|
| **Communication** | Two separate pipes | Single duplex named pipe |
| **Process Creation** | `fork()` | `CreateProcess()` |
| **Native Mode** | Available (dlfcn) | Not available |
| **Pipe Access** | Separate read/write FDs | Same handle for both |
| **Protocol** | Byte-stream oriented | Message oriented |

## Similarities

- Both use environment variables (`R2PIPE_IN`, `R2PIPE_OUT`) for configuration
- Both support HTTP mode for remote radare2 instances
- Both implement the same command/response protocol
- Both handle process lifecycle management
- Go wrapper provides consistent API across platforms

## Error Handling

### Unix
- Pipe creation failures
- Fork failures
- Child process termination detection
- Signal handling for cleanup

### Windows
- Named pipe creation/connection failures
- Process handle management
- Overlapped I/O considerations (though not used in current impl)

## Future Considerations

- Windows native mode could potentially be implemented using `LoadLibrary()` and `GetProcAddress()`
- Unix could potentially use socketpairs instead of pipes for cleaner duplex communication
- Cross-platform socket-based communication could unify the implementations

## References

- C implementation: `radare2/libr/socket/r2pipe.c`
- Go wrapper: `r2pipe.go`, `r2pipe_unix.go`, `r2pipe_windows.go`, `native.go`