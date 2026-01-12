package r2pipe

import "testing"
import "fmt"
import "time"

func TestErrSide(t *testing.T) {
	r2p, err := NewPipe("malloc://256")
	if err != nil {
		t.Fatal(err)
	}
	_ = r2p.Close()
	var res = false
	_ = r2p.On("errmsg", res, func(p *Pipe, typ string, user interface{}, dat string) bool {
		fmt.Println("errmsg received")
		res = true
		return false
		// return true
	})

	_, _ = r2p.Cmd("aaa")
	time.Sleep(100 * time.Millisecond)
	if res {
		fmt.Println("It works!")
	}
	defer func() { _ = r2p.Close() }()
	fmt.Println("[*] Testing r2pipe-side stderr message")
}
