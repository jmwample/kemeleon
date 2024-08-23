
test:
	cargo test --all-features -- --test-threads=1 --nocapture $(ARGS)

doc:
	RUSTDOCFLAGS="--html-in-header doc/katex-header.html" cargo doc --no-deps $(ARGS)

.PHONY: doc test
