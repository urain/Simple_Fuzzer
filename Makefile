all: simple_fuzzer

simple_fuzzer: simple_fuzzer.c
	cc simple_fuzzer.c -o simple_fuzzer

clean:
	rm -f simple_fuzzer