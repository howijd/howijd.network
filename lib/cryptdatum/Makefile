.PHONY: test clean

clean:
	rm -rf cryptdatum_test_c
	rm -rf target

test: clean
	# C
	gcc -o cryptdatum_test_c cryptdatum_test.c cryptdatum.c && ./cryptdatum_test_c

	# rust
	cargo test

	# GO
	go test -race -cover .
