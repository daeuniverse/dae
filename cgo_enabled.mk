#
#  SPDX-License-Identifier: AGPL-3.0-only
#  Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
#

ifneq ($(KEEP_CGO_ENVS),1)
	ifdef CGO_ENABLED_NDEF
export CGO_ENABLED := 0
	endif
	ifeq ($(CGO_ENABLED),0)
		ifdef GOARCH_NDEF
			ifeq ($(CC),cc)
				ifneq ($(shell which musl-gcc),)
export CC := musl-gcc
				else ifneq ($(shell which zig),)
export CC := zig cc -target $(shell . install/musl-targets.sh && echo $$GOARCH_$(GOARCH))
				else
$(info ! CGO_ENABLED=0 is not recommended. Please consider to install musl-gcc for static link instead. See https://github.com/daeuniverse/dae/issues/557)
				endif
			endif
		else ifneq ($(shell which zig),)
export CC := zig cc -target $(shell . install/musl-targets.sh && echo $$GOARCH_$(GOARCH))
		else
$(info ! CGO_ENABLED=0 is not recommended. See https://github.com/daeuniverse/dae/issues/557)
		endif
	endif
	ifneq ($(CC),cc)
export CGO_ENABLED := 1
GO_LDFLAGS += -linkmode external -extldflags=-static
$(info * Building dae with "$(CC)" static linking instead of CGO_ENABLED=0. See https://github.com/daeuniverse/dae/issues/557)
	endif
endif
