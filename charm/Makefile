CHARM=/snap/bin/charm

.PHONY: build
build:
	CHARM_INTERFACES_DIR=interfaces $(CHARM) build --build-dir build layer-candid

.PHONY: lint
lint:
	@# ls -d hooks/* | grep -v -E '/(install|charmhelpers)$'
	flake8 \
		layer-candid/reactive/candid.py \
		layer-candid/lib/charms/layer/candid.py
			
.PHONY: clean
clean:
	-rm -rf build
