
all: module/vuln.ko example/example

module/vuln.ko: module/main.c module/vuln.h
	(cd module && make)

example/example: example/main.c
	(cd example && make)

clean:
	(cd module && make clean)
	(cd example && make clean)
