package lifecyclejobs

import "time"

// VerifyBackoff is the CLM-owned pending_verify schedule (migrate / renew).
var VerifyBackoff = []time.Duration{
	10 * time.Second,
	30 * time.Second,
	60 * time.Second,
	5 * time.Minute,
	30 * time.Minute,
	60 * time.Minute,
	3 * time.Hour,
	6 * time.Hour,
}

// NextVerifyDelay returns the delay before the next verify attempt.
// attempt is 1-based after a miss; values beyond the table use the last step.
func NextVerifyDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > len(VerifyBackoff) {
		return VerifyBackoff[len(VerifyBackoff)-1]
	}
	return VerifyBackoff[attempt-1]
}

// VerifyDelay is the plan alias for NextVerifyDelay (1-based attempt).
func VerifyDelay(attempt int) time.Duration {
	return NextVerifyDelay(attempt)
}

// NextVerifyAt returns when the next probe should run. If the delay would land
// at or past timeoutAt, next is timeoutAt and last is true (final attempt).
func NextVerifyAt(now time.Time, attempt int, timeoutAt time.Time) (time.Time, bool) {
	next := now.Add(VerifyDelay(attempt))
	if !next.Before(timeoutAt) {
		return timeoutAt, true
	}
	return next, false
}
