/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import "testing"

// supervisorSnapshotForTest reads the supervisor's generation pointers under
// its lock for test assertions. The production snapshot accessor was removed
// as dead code; tests observe supervisor state through this helper instead.
func supervisorSnapshotForTest(s *runtimeSupervisor) runtimeSupervisorSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return runtimeSupervisorSnapshot{
		active:   s.active,
		prepared: s.prepared,
		retiring: s.retiring,
	}
}

func FuzzRuntimeSupervisorOperations(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5})
	f.Add([]byte{1, 0, 1, 3, 0, 2, 5, 1})
	f.Add([]byte{0, 0, 2, 0, 1, 3, 4, 5, 0})

	f.Fuzz(func(t *testing.T, operations []byte) {
		active := newTestRuntimeGeneration()
		supervisor := newRuntimeSupervisor(active)
		candidates := make([]*runtimeGeneration, 0, len(operations))

		assertState := func() {
			snapshot := supervisorSnapshotForTest(supervisor)
			if snapshot.active != nil && snapshot.active == snapshot.prepared {
				t.Fatal("active and prepared generations alias")
			}
			if snapshot.active != nil && snapshot.active == snapshot.retiring {
				t.Fatal("active and retiring generations alias")
			}
			if snapshot.prepared != nil && snapshot.prepared == snapshot.retiring {
				t.Fatal("prepared and retiring generations alias")
			}
			if supervisor.closed && (snapshot.active != nil || snapshot.prepared != nil || snapshot.retiring != nil) {
				t.Fatal("closed supervisor retained generation ownership")
			}
		}

		for _, operation := range operations {
			snapshot := supervisorSnapshotForTest(supervisor)
			switch operation % 7 {
			case 0:
				candidate := newTestRuntimeGeneration()
				candidates = append(candidates, candidate)
				_ = supervisor.installPrepared(candidate)
			case 1:
				if snapshot.prepared != nil {
					if next, err := supervisor.publishPrepared(snapshot.prepared); err == nil {
						active = snapshot.prepared
						_ = next
					}
				}
			case 2:
				if snapshot.prepared != nil {
					supervisor.rollbackPrepared(snapshot.prepared)
				}
			case 3:
				if snapshot.retiring != nil {
					supervisor.markRetirementComplete(snapshot.retiring)
				}
			case 4:
				if active != nil {
					_ = supervisor.replaceActive(active)
				}
			case 5:
				_ = supervisor.shutdown()
			case 6:
				if len(candidates) > 0 {
					supervisor.rollbackPrepared(candidates[len(candidates)-1])
				}
			}
			assertState()
		}
		if !supervisor.closed {
			_ = supervisor.shutdown()
		}
		assertState()
	})
}
