// radare - LGPL - Copyright 2017 - pancake

package r2pipe

//#include <dlfcn.h>
// #include <stdlib.h>
import "C"

import (
	"errors"
	"unsafe"
)

type Ptr = *struct{}

var (
	lib            Ptr = nil
	r_core_new     func() Ptr
	r_core_free    func(Ptr)
	r_mem_free     func(interface{})
	r_core_cmd_str func(Ptr, string) string
)

type DL struct {
	handle unsafe.Pointer
}
func dlOpen(path string) (*DL, error){
	var ret DL
	cpath := C.CString(path)
	if cpath == nil {
		return nil, errors.New("Failed to get cpath")
	}
	//r2pioe only uses flag 0
	ret.handle = C.dlopen(cpath, 0)
	C.free(unsafe.Pointer(cpath))
	if ret.handle == nil {
		return nil, errors.New("Failed to open dl")
	}
	return &ret, nil
}

func (dl *DL) symFunc(name string, out interface{}) error {
	cname := C.CString(name)
	if cname ==>nil {
		return
	}
}

func NativeLoad() error {
	if lib != nil {
		return nil
	}
	lib, err := dlOpen("libr_core")
	if err != nil {
		return err
	}
	if lib.symFunc("r_core_new", &r_core_new) != nil {
		return errors.New("Missing r_core_new")
	}
	if lib.symFunc("r_core_cmd_str", &r_core_cmd_str) != nil {
		return errors.New("Missing r_core_cmd_str")
	}
	if lib.symFunc("r_core_free", &r_core_free) != nil {
		return errors.New("Missing r_core_free")
	}
	if lib.symFunc("r_mem_free", &r_mem_free) != nil {
		return errors.New("Missing r_mem_free")
	}
	return nil
}

func (r2p *Pipe) NativeCmd(cmd string) (string, error) {
	res := r_core_cmd_str(r2p.Core, cmd)
	return res, nil
}

func (r2p *Pipe) NativeClose() error {
	r_core_free(r2p.Core)
	r2p.Core = nil
	return nil
}

func NewNativePipe(file string) (*Pipe, error) {
	if err := NativeLoad(); err != nil {
		return nil, err
	}
	r2 := r_core_new()
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
		r2p.NativeCmd("o " + file)
	}
	return r2p, nil
}
