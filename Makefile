build-wasm:
	RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build --release --target web

build-wasm-compat:
	RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build --release --target web --features wasm-compat-test

check-wasm:
	RUSTFLAGS='--cfg getrandom_backend="wasm_js"' cargo check --target wasm32-unknown-unknown --no-default-features --features wasm-js

# The unit tests are compiled for wasm32 too (wasm-pack builds the harness), so
# a cfg'd-out import in a test module breaks the browser test job before any
# browser runs. Building the harness here is the cheap local equivalent.
check-wasm-tests:
	RUSTFLAGS='--cfg getrandom_backend="wasm_js"' cargo build --tests --target wasm32-unknown-unknown

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

# The two surfaces do not compile together (see README "Documentation"), so each
# is documented on its own. docs.rs builds the browser one for releases; the
# docs workflow publishes both to GitHub Pages.
doc: doc-native

doc-native:
	cargo doc --no-deps --no-default-features --features native,keyring,pem,android-password,tracing --open

doc-wasm:
	RUSTFLAGS='--cfg getrandom_backend="wasm_js"' cargo doc --no-deps --target wasm32-unknown-unknown --no-default-features --features wasm-js,tracing --open

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
