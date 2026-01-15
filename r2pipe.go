// radare - LGPL - Copyright 2015 - nibble

/*
Package r2pipe allows to call r2 commands from Go. A simple hello world would
look like the following snippet:

	package main

	import (
		"fmt"

		"github.com/radare/r2pipe-go"
	)

	func main() {
		r2p, err := r2pipe.NewPipe("malloc://256")
		if err != nil {
			panic(err)
		}
		defer r2p.Close()

		_, err = r2p.Cmd("w Hello World")
		if err != nil {
			panic(err)
		}
		buf, err := r2p.Cmd("ps")
		if err != nil {
			panic(err)
		}
		fmt.Println(buf)
	}
*/
package r2pipe

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"unsafe"
)

// A Pipe represents a communication interface with r2 that will be used to
// execute commands and obtain their results.
type Pipe struct {
	File   string
	r2cmd  *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	stderr io.ReadCloser
	Core   unsafe.Pointer
	cmd    CmdDelegate
	close  CloseDelegate
}

type (
	CmdDelegate   func(*Pipe, string) (string, error)
	CloseDelegate func(*Pipe) error
	EventDelegate func(*Pipe, string, interface{}, string) bool
)

// NewPipe returns a new r2 pipe and initializes an r2 core that will try to
// load the provided file or URI. If file is an empty string, the env vars
// R2PIPE_{IN,OUT} will be used as file descriptors for input and output, this
// is the case when r2pipe is called within r2.
func NewPipe(file string) (*Pipe, error) {
	if file == "" {
		return newPipeFd()
	}

	return newPipeCmd(file)
}

func newPipeFd() (*Pipe, error) {
	r2pipeIn := os.Getenv("R2PIPE_IN")
	r2pipeOut := os.Getenv("R2PIPE_OUT")

	if r2pipeIn == "" || r2pipeOut == "" {
		return nil, errors.New("missing R2PIPE_{IN,OUT} environment variables")
	}

	r2pipeInFd, err := strconv.Atoi(r2pipeIn)
	if err != nil {
		return nil, fmt.Errorf("failed to parse R2PIPE_IN environment variable as integer: %w", err)
	}

	r2pipeOutFd, err := strconv.Atoi(r2pipeOut)
	if err != nil {
		return nil, fmt.Errorf("failed to parse R2PIPE_OUT environment variable as integer: %w", err)
	}

	stdout := os.NewFile(uintptr(r2pipeInFd), "R2PIPE_IN")
	stdin := os.NewFile(uintptr(r2pipeOutFd), "R2PIPE_OUT")

	r2p := &Pipe{
		File:   "",
		r2cmd:  nil,
		stdin:  stdin,
		stdout: stdout,
		Core:   nil,
	}

	return r2p, nil
}


// Write implements the standard Write interface: it writes data to the r2
// pipe, blocking until r2 have consumed all the data.
func (r2p *Pipe) Write(p []byte) (n int, err error) {
	return r2p.stdin.Write(p)
}

// Read implements the standard Read interface: it reads data from the r2
// pipe's stdin, blocking until the previously issued commands have finished.
func (r2p *Pipe) Read(p []byte) (n int, err error) {
	return r2p.stdout.Read(p)
}

func (r2p *Pipe) ReadErr(p []byte) (n int, err error) {
	return r2p.stderr.Read(p)
}

// On registers an event handler for radare2 events.
func (r2p *Pipe) On(evname string, p interface{}, cb EventDelegate) error {
	path, err := r2p.Cmd("===stderr")
	if err != nil {
		return fmt.Errorf("failed to get stderr path: %w", err)
	}

	f, err := os.OpenFile(path, os.O_RDONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open stderr file %q: %w", path, err)
	}

	go func() {
		defer func() {
			if err := f.Close(); err != nil {
				// In a real implementation, we might log this
				_ = err
			}
		}()

		var buf bytes.Buffer
		for {
			_, _ = io.Copy(&buf, f)
			if buf.Len() > 0 {
				if !cb(r2p, evname, p, buf.String()) {
					break
				}
			}
		}
	}()
	return nil
}

// Cmd executes a radare2 command and returns the response.
// The command string should not include a newline character.
// Example:
//
//	response, err := pipe.Cmd("iI")
//	if err != nil {
//		return err
//	}
func (r2p *Pipe) Cmd(cmd string) (string, error) {
	if cmd == "" {
		return "", errors.New("command cannot be empty")
	}

	if r2p.Core != nil {
		if r2p.cmd != nil {
			return r2p.cmd(r2p, cmd)
		}
		return "", nil
	}

	if r2p.stdin == nil {
		return "", errors.New("stdin pipe is not initialized")
	}

	if _, err := fmt.Fprintln(r2p, cmd); err != nil {
		return "", fmt.Errorf("failed to write command %q: %w", cmd, err)
	}

	if r2p.stdout == nil {
		return "", errors.New("stdout pipe is not initialized")
	}

	buf, err := bufio.NewReader(r2p).ReadString('\x00')
	if err != nil {
		return "", fmt.Errorf("failed to read response from command %q: %w", cmd, err)
	}
	return strings.TrimRight(buf, "\n\x00"), nil
}

// like cmd but formats the command
func (r2p *Pipe) Cmdf(f string, args ...interface{}) (string, error) {
	return r2p.Cmd(fmt.Sprintf(f, args...))
}

// Cmdj acts like Cmd but interprets the output of the command as json.
// It returns the parsed json keys and values.
func (r2p *Pipe) Cmdj(cmd string) (out interface{}, err error) {
	rstr, err := r2p.Cmd(cmd)
	if err != nil {
		return out, fmt.Errorf("failed to execute command %q: %w", cmd, err)
	}

	if err := json.Unmarshal([]byte(rstr), out); err != nil {
		return out, fmt.Errorf("failed to parse JSON response from command %q: %w", cmd, err)
	}
	return out, nil
}

// CmdjStruct acts like Cmd but parses the JSON response into the provided struct.
// It returns the command execution error.
func (r2p *Pipe) CmdjStruct(cmd string, out interface{}) error {
	if out == nil {
		return errors.New("output struct cannot be nil")
	}

	rstr, err := r2p.Cmd(cmd)
	if err != nil {
		return fmt.Errorf("failed to execute command %q: %w", cmd, err)
	}

	if err := json.Unmarshal([]byte(rstr), out); err != nil {
		return fmt.Errorf("failed to parse JSON response from command %q into struct: %w", cmd, err)
	}
	return nil
}

// like cmdj but formats the command
func (r2p *Pipe) Cmdjf(f string, args ...interface{}) (interface{}, error) {
	return r2p.Cmdj(fmt.Sprintf(f, args...))
}

// like Cmdj, but besides format the command it will already fill the interface sent
func (r2p *Pipe) CmdjfStruct(f string, out interface{}, args ...interface{}) error {
	return r2p.CmdjStruct(fmt.Sprintf(f, args...), out)
}

// Close shuts down r2, closing the created pipe.
// It gracefully sends the quit command and waits for the process to exit.
func (r2p *Pipe) Close() error {
	if r2p.close != nil {
		return r2p.close(r2p)
	}

	if r2p.File == "" {
		return nil
	}

	// Send quit command to r2
	if _, err := r2p.Cmd("q"); err != nil {
		// Log the error but continue with process cleanup
		_ = err
	}

	if r2p.r2cmd == nil || r2p.r2cmd.Process == nil {
		return nil
	}

	// Wait for the process to exit
	if err := r2p.r2cmd.Wait(); err != nil {
		return fmt.Errorf("failed to wait for radare2 process exit: %w", err)
	}

	return nil
}

// ForceClose performs a forced shutdown of r2, closing the created pipe.
// It sends the force-quit command and waits for the process to exit.
func (r2p *Pipe) ForceClose() error {
	if r2p.close != nil {
		return r2p.close(r2p)
	}

	if r2p.File == "" {
		return nil
	}

	// Send force quit command to r2
	if _, err := r2p.Cmd("q!"); err != nil {
		// Log the error but continue with process cleanup
		_ = err
	}

	if r2p.r2cmd == nil || r2p.r2cmd.Process == nil {
		return nil
	}

	// Wait for the process to exit
	if err := r2p.r2cmd.Wait(); err != nil {
		return fmt.Errorf("failed to wait for radare2 process exit: %w", err)
	}

	return nil
}
