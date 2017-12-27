all:
	gcc test_aes.c kcaes.c -o test_aes
clean:
	rm test_aes
