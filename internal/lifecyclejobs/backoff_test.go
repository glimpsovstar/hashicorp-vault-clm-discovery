package lifecyclejobs

import (
	"testing"
	"time"
)

func TestNextVerifyDelay(t *testing.T) {
	t.Parallel()
	if NextVerifyDelay(1) != 10*time.Second {
		t.Fatal(NextVerifyDelay(1))
	}
	if NextVerifyDelay(3) != 60*time.Second {
		t.Fatal(NextVerifyDelay(3))
	}
	if NextVerifyDelay(8) != 6*time.Hour {
		t.Fatal(NextVerifyDelay(8))
	}
	if NextVerifyDelay(99) != 6*time.Hour {
		t.Fatal("cap")
	}
	if NextVerifyDelay(0) != 10*time.Second {
		t.Fatal("zero")
	}
}
