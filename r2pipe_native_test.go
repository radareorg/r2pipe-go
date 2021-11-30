// radare - LGPL - Copyright 2017-2021 - pancake

package r2pipe

import "testing"
import "fmt"

func TestNativeCmd(t *testing.T) {
	fmt.Println("[*] Testing r2 native api pipe")
	r2p, err := NewNativePipe("/bin/ls")
	// r2p, err := NewPipe("/bin/ls")
	if err != nil {
		t.Fatal(err)
	}
	defer r2p.Close()
	version, err := r2p.Cmd("pd 10 @ entry0")
	if err != nil {
		t.Fatal(err)
	}
	print(version + "\n")
}
