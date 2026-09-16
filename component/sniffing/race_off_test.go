//go:build !race

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

// raceEnabled reports whether this binary was built with the race detector. The
// allocation budgets below describe production builds: the detector instruments
// every allocation, so the same code measures higher under -race and the budget
// would fail for a reason that has nothing to do with the sniffing path.
const raceEnabled = false
