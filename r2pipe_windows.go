// +build windows

package r2pipe

import (
	"fmt"
	"os"
	"os/exec"

	"golang.org/x/sys/windows"
)

func newPipeCmd(file string) (*Pipe, error) {
	pipeName := `\\.\pipe\R2PIPE_IN`
	pipeHandle, err := windows.CreateNamedPipe(
		windows.StringToUTF16Ptr(pipeName),
		windows.PIPE_ACCESS_DUPLEX,
		windows.PIPE_TYPE_MESSAGE|windows.PIPE_READMODE_MESSAGE|windows.PIPE_WAIT,
		windows.PIPE_UNLIMITED_INSTANCES,
		4096,
		4096,
		0,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create named pipe: %w", err)
	}

	r2p := &Pipe{File: file}

	// Start the radare2 process
	r2p.r2cmd = exec.Command("radare2", "-q0", file)

	// Set the environment for the child to use the pipe
	r2p.r2cmd.Env = append(os.Environ(), "R2PIPE_IN="+pipeName)

	// stderr is optional
	r2p.stderr, _ = r2p.r2cmd.StderrPipe()

	err = r2p.r2cmd.Start()
	if err != nil {
		windows.CloseHandle(pipeHandle)
		return nil, fmt.Errorf("failed to start radare2 process: %w", err)
	}

	// Connect to the pipe
	err = windows.ConnectNamedPipe(pipeHandle, nil)
	if err != nil {
		windows.CloseHandle(pipeHandle)
		r2p.r2cmd.Process.Kill()
		return nil, fmt.Errorf("failed to connect to named pipe: %w", err)
	}

	// Create os.File from the handle for stdin/stdout
	r2p.stdin = os.NewFile(uintptr(pipeHandle), "R2PIPE_IN")
	r2p.stdout = r2p.stdin // same handle for duplex

	return r2p, nil
}