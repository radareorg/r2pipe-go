// +build !windows

package r2pipe

import (
	"bufio"
	"fmt"
	"os/exec"
)

func newPipeCmd(file string) (*Pipe, error) {
	r2p := &Pipe{File: file, r2cmd: exec.Command("radare2", "-q0", file)}

	var err error
	r2p.stdin, err = r2p.r2cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	r2p.stdout, err = r2p.r2cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	// stderr is optional, but log the error
	r2p.stderr, _ = r2p.r2cmd.StderrPipe()

	if err := r2p.r2cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start radare2 process: %w", err)
	}

	// Read the initial null terminator to confirm process readiness
	_, err = bufio.NewReader(r2p.stdout).ReadString('\x00')
	if err != nil {
		_ = r2p.r2cmd.Wait() // attempt cleanup
		return nil, fmt.Errorf("failed to read initial response from radare2: %w", err)
	}

	return r2p, nil
}