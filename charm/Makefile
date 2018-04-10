.PHONY: build
build: hooks/charmhelpers

hooks/charmhelpers: charm-helpers.yaml
	./charm_helpers_sync.py -c charm-helpers.yaml

.PHONY: lint
lint:
	flake8 hooks/config-changed hooks/db-relation-changed hooks/install.py hooks/jaascharm.py hooks/nrpe-relation-changed hooks/status.py hooks/stop hooks/update-status hooks/upgrade-charm hooks/website-relation-joined

.PHONY: clean
clean:
	-rm -rf hooks/charmhelpers
