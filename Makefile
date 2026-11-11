build-wasm:
	RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build --release --target web

build-wasm-compat:
	RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build --release --target web --features wasm-compat-test

check-wasm:
	RUSTFLAGS='--cfg getrandom_backend="wasm_js"' cargo check --target wasm32-unknown-unknown --no-default-features --features wasm-js

check-native-keyring:
	cargo check --no-default-features --features native,keyring

check-native-pem:
	cargo check --no-default-features --features native,pem

test-native-keyring:
	cargo test --no-default-features --features native,keyring

test-native-pem:
	cargo test --no-default-features --features native,pem

check-agent-compat:
	./scripts/check-agent-compat.sh

bump-ic-agent:
	@test -n "$(VERSION)" || (echo "usage: make bump-ic-agent VERSION=0.50.0" && false)
	./scripts/bump-ic-agent.sh "$(VERSION)"

test-chrome:
	RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack test --chrome

test-firefox:
	RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack test --firefox

test-safari:
	RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack test --safari

doc:
	RUSTDOCFLAGS='--cfg docsrs' cargo +nightly doc --features keyring,pem,native,tracing,wasm-js --no-deps --open

build-swift:
	./swift-package/IcAuthClient/build_all.sh

build-kotlin:
	./kotlin-package/IcAuthClient/build_all.sh

clean:
	rm -rf target
	rm -rf pkg
	cargo clean

clean-example-builds:
	find examples -type d \( -name target -o -name .dfx -o -name dist \) -prune -exec rm -rf {} +
