.PHONY: build
build: hooks/charmhelpers

hooks/charmhelpers: charm-helpers.yaml
	./charm_helpers_sync.py -c charm-helpers.yaml

.PHONY: lint
lint:
	@# ls -d hooks/* | grep -v -E '/(install|charmhelpers)$'
	flake8 \
		hooks/config-changed \
		hooks/install.py \
		hooks/jaascharm.py \
		hooks/mongodb-relation-changed \
		hooks/nrpe-relation-changed \
		hooks/postgres-relation-changed \
		hooks/status.py \
		hooks/stop \
		hooks/update-status \
		hooks/upgrade-charm \
		hooks/website-relation-joined \
			
.PHONY: clean
clean:
	-rm -rf hooks/charmhelpers
