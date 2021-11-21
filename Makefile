all:
	go test

ex:
	cd example ; go run example.go

sync:
	git clone --depth=1 https://github.com/radareorg/radare2-r2pipe
	cp -rf radare2-r2pipe/go/*.go .
	rm -rf radare2-r2pipe

.PHONY: all sync
