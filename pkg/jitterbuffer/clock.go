// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package jitterbuffer

import "time"

// Timer is a countdown that fires a callback once. It mirrors the subset of
// time.Timer used by Buffer so tests can substitute a controlled clock.
type Timer interface {
	// Stop prevents the timer from firing. It reports whether the callback
	// had not yet fired.
	Stop() bool
}

// Clock abstracts time so tests can replay wraparound, gap filling and
// timeout scenarios without sleeping.
type Clock interface {
	// Now returns the current time.
	Now() time.Time
	// AfterFunc schedules f to run after d. The callback must not run
	// synchronously inside AfterFunc.
	AfterFunc(d time.Duration, f func()) Timer
}

// RealClock is a Clock backed by the time package.
type RealClock struct{}

// Now implements Clock.
func (RealClock) Now() time.Time { return time.Now() }

// AfterFunc implements Clock.
func (RealClock) AfterFunc(d time.Duration, f func()) Timer {
	return time.AfterFunc(d, f)
}
