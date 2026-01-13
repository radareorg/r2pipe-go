// radare - LGPL - Copyright 2017 - pancake

package r2pipe

//#cgo linux LDFLAGS: -ldl
//#cgo darwin LDFLAGS: -ldl
//#include <stdio.h>
//#include <dlfcn.h>
// #include <stdlib.h>
// #ifndef RTLD_NOW
// #define RTLD_NOW 0x2
// #endif
// #ifndef RTLD_GLOBAL
// #define RTLD_GLOBAL 0x100
// #endif
// void *gor_core_new(void *f) {
// 	void *(*rcn)();
// 	rcn = (void *(*)())f;
// 	return rcn();
// }
//
// void gor_core_free(void *f, void *arg) {
// 	void (*fr)(void *);
// 	fr = (void (*)(void *))f;
// 	fr(arg);
// }
//
// char *gor_core_cmd_str(void *f, void *arg, char *arg2) {
// 	char *(*cmdstr)(void *, char *);
// 	cmdstr = (char *(*)(void *, char *))f;
// 	return cmdstr(arg, arg2);
// }
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"
)

type Ptr = unsafe.Pointer

// *struct{}

var (
	lib            *DL = nil
	r_core_new     func() Ptr
	r_core_free    func(Ptr)
	r_core_cmd_str func(Ptr, string) string
)

type DL struct {
	handle unsafe.Pointer
	name   string
}

func dlOpen(path string) (*DL, error) {
	var ret DL
	var ext string
	switch runtime.GOOS {
	case "darwin":
		ext = ".dylib"
	case "windows":
		ext = ".dll"
	default:
		ext = ".so" //linux/bsds
	}

	paths := []string{
		path + ext,
		"/usr/lib/" + path + ext,
		"/usr/local/lib/" + path + ext,
		"/opt/homebrew/lib/" + path + ext, // Apple Silicon Homebrew
	}

	// Add Linux multiarch paths if running on Linux
	if runtime.GOOS == "linux" {
		linuxPaths := []string{
			"/usr/lib/x86_64-linux-gnu/" + path + ext, // Ubuntu/Debian 64-bit
			"/usr/lib/i386-linux-gnu/" + path + ext,   // Ubuntu/Debian 32-bit
			"/usr/lib64/" + path + ext,                // Generic 64-bit path
			"/usr/lib32/" + path + ext,                // Generic 32-bit path
		}
		paths = append(paths, linuxPaths...)
	}

	for _, p := range paths {
		cpath := C.CString(p)
		if cpath == nil {
			continue
		}
		// Use RTLD_NOW|RTLD_GLOBAL to properly load library and its dependencies
		ret.handle = C.dlopen(cpath, C.RTLD_NOW|C.RTLD_GLOBAL)
		ret.name = p
		C.free(unsafe.Pointer(cpath))
		if ret.handle != nil {
			return &ret, nil
		}
	}

	return nil, fmt.Errorf("failed to open %s in standard paths", path)
}

func dlSym(dl *DL, name string) (unsafe.Pointer, error) {
	cname := C.CString(name)
	if cname == nil {
		return nil, fmt.Errorf("failed to allocate C string for symbol name %q", name)
	}
	defer C.free(unsafe.Pointer(cname))

	handle := C.dlsym(dl.handle, cname)
	if handle == nil {
		return nil, fmt.Errorf("failed to load symbol %q from %q", name, dl.name)
	}
	return handle, nil
}

// NativeLoad loads the native radare2 library and initializes function pointers.
func NativeLoad() error {
	if lib != nil {
		return nil
	}

	var err error
	lib, err = dlOpen("libr_core")
	if err != nil {
		return fmt.Errorf("failed to load native libr_core: %w", err)
	}

	handle1, err := dlSym(lib, "r_core_new")
	if err != nil {
		return fmt.Errorf("failed to load r_core_new symbol: %w", err)
	}
	r_core_new = func() Ptr {
		a := (Ptr)(C.gor_core_new(handle1))
		return a
	}

	handle2, err := dlSym(lib, "r_core_free")
	if err != nil {
		return fmt.Errorf("failed to load r_core_free symbol: %w", err)
	}
	r_core_free = func(p Ptr) {
		C.gor_core_free(handle2, unsafe.Pointer(p))
	}

	handle3, err := dlSym(lib, "r_core_cmd_str")
	if err != nil {
		return fmt.Errorf("failed to load r_core_cmd_str symbol: %w", err)
	}
	r_core_cmd_str = func(p Ptr, s string) string {
		a := C.CString(s)
		if a == nil {
			return ""
		}
		defer C.free(unsafe.Pointer(a))
		b := C.gor_core_cmd_str(handle3, unsafe.Pointer(p), a)
		return C.GoString(b)
	}

	return nil
}

// NativeCmd executes a command using the native radare2 library.
func (r2p *Pipe) NativeCmd(cmd string) (string, error) {
	if cmd == "" {
		return "", fmt.Errorf("command cannot be empty")
	}
	if r2p.Core == nil {
		return "", fmt.Errorf("radare2 core is not initialized")
	}

	res := r_core_cmd_str(r2p.Core, cmd)
	return res, nil
}

// NativeClose frees the native radare2 core instance.
func (r2p *Pipe) NativeClose() error {
	if r2p.Core == nil {
		return nil
	}
	r_core_free(r2p.Core)
	r2p.Core = nil
	return nil
}

// NewNativePipe creates a new pipe using the native radare2 library.
func NewNativePipe(file string) (*Pipe, error) {
	if err := NativeLoad(); err != nil {
		return nil, fmt.Errorf("failed to load native radare2 library: %w", err)
	}

	r2 := r_core_new()
	if r2 == nil {
		return nil, fmt.Errorf("failed to create radare2 core instance")
	}

	r2p := &Pipe{
		File: file,
		Core: r2,
		cmd: func(r2p *Pipe, cmd string) (string, error) {
			return r2p.NativeCmd(cmd)
		},
		close: func(r2p *Pipe) error {
			return r2p.NativeClose()
		},
	}

	if file != "" {
		_, err := r2p.NativeCmd("o " + file)
		if err != nil {
			// Log the error but don't fail; the file might be openable later
			_ = err
		}
	}

	return r2p, nil
}
