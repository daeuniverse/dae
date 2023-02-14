/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, v2rayA Organization <team@v2raya.org>
 */

package sniffing

import (
	"errors"
	"fmt"
)

var (
	Error              = fmt.Errorf("sniffing error")
	NotApplicableError = fmt.Errorf("%w: not applicable", Error)
	NotFoundError      = fmt.Errorf("%w: not found", Error)
)

func IsSniffingError(err error) bool {
	return errors.Is(err, Error)
}
