candid:
	cargo build -p backend --release --target wasm32-unknown-unknown
	candid-extractor target/wasm32-unknown-unknown/release/backend.wasm > .candid/backend.did

build-frontend:
	trunk build --release

build-backend:
	cargo build -p backend --release --target wasm32-unknown-unknown

clean:
	rm -rf .dfx
	rm -rf crates/frontend/dist
	rm -rf target
	rm -f .env
	cargo clean
