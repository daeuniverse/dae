#
#  SPDX-License-Identifier: AGPL-3.0-only
#  Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
#
ifneq ($(KEEP_CGO_ENVS),1)
	ifndef CGO_ENABLED
	export CGO_ENABLED := 0
	endif
	ifeq ($(shell go env CGO_ENABLED),0)
		ifneq ($(shell which musl-gcc),)
export CGO_ENABLED := 1
export CC := musl-gcc
GO_LDFLAGS += -linkmode external -extldflags=-static
$(info * Building dae with musl-gcc static linking instead of CGO_ENABLED=0. See https://github.com/daeuniverse/dae/issues/557)
		else
$(info ! CGO_ENABLED=0 is not recommended. Use static link instead. See https://github.com/daeuniverse/dae/issues/557)
		endif
	endif
else
	export CGO_ENABLED := 0
endif
