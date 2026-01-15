// radare - LGPL - Copyright 2021 - pancake

package r2pipe

// #cgo CFLAGS: -I/usr/local/include/libr
// #cgo CFLAGS: -I/usr/local/include/libr/sdb
// #cgo LDFLAGS: -L/usr/local/lib -lr_core
// #cgo windows CFLAGS: -I./radare2/include/libr -I./radare2/include/libr/sdb
// #cgo windows LDFLAGS: -L./radare2/bin -lr_core
// #cgo !windows pkg-config: r_core
// #include <stdio.h>
// #include <stdlib.h>
// extern void r_core_free(void *);
// extern void *r_core_new(void);
// extern char *r_core_cmd_str(void*, const char *);
//
import "C"

import (
	"fmt"
	"unsafe"
)

// ApiCmd executes a command using the C API.
func (r2p *Pipe) ApiCmd(cmd string) (string, error) {
	if cmd == "" {
		return "", fmt.Errorf("command cannot be empty")
	}
	if r2p.Core == nil {
		return "", fmt.Errorf("radare2 core is not initialized")
	}

	cstr := C.CString(cmd)
	if cstr == nil {
		return "", fmt.Errorf("failed to allocate C string for command %q", cmd)
	}
	defer C.free(unsafe.Pointer(cstr))

	res := C.r_core_cmd_str(r2p.Core, cstr)
	if res == nil {
		return "", nil
	}

	return C.GoString(res), nil
}

// ApiClose frees the radare2 core instance.
func (r2p *Pipe) ApiClose() error {
	if r2p.Core == nil {
		return nil
	}
	C.r_core_free(unsafe.Pointer(r2p.Core))
	r2p.Core = nil
	return nil
}

// NewApiPipe creates a new pipe using the C API.
func NewApiPipe(file string) (*Pipe, error) {
	r2 := C.r_core_new()
	if r2 == nil {
		return nil, fmt.Errorf("failed to create radare2 core instance")
	}

	r2p := &Pipe{
		File: file,
		Core: r2,
		cmd: func(r2p *Pipe, cmd string) (string, error) {
			return r2p.ApiCmd(cmd)
		},
		close: func(r2p *Pipe) error {
			return r2p.ApiClose()
		},
	}

	if file != "" {
		_, err := r2p.ApiCmd("o " + file)
		if err != nil {
			// Log the error but don't fail; the file might be openable later
			_ = err
		}
	}

	return r2p, nil
}
