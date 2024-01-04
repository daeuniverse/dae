/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"errors"
	"fmt"
)

var (
	Error            = fmt.Errorf("sniffing error")
	ErrNotApplicable = fmt.Errorf("%w: not applicable", Error)
	ErrNotFound      = fmt.Errorf("%w: not found", Error)
)

func IsSniffingError(err error) bool {
	return errors.Is(err, Error)
}
