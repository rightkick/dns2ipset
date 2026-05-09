package dedup

import (
	"testing"
	"time"
)

func TestDedup_RepeatWithinWindowIsDup(t *testing.T) {
	d, _ := New(128, 200*time.Millisecond)
	payload := []byte{1, 2, 3, 4}
	if d.Seen(payload) {
		t.Fatal("first call must report not-seen")
	}
	if !d.Seen(payload) {
		t.Fatal("second call within TTL must report seen")
	}
}

func TestDedup_DifferentPayloadsIndependent(t *testing.T) {
	d, _ := New(128, time.Second)
	if d.Seen([]byte("a")) {
		t.Fatal("a first")
	}
	if d.Seen([]byte("b")) {
		t.Fatal("b first")
	}
	if !d.Seen([]byte("a")) || !d.Seen([]byte("b")) {
		t.Fatal("repeats should match")
	}
}

func TestDedup_TTLExpires(t *testing.T) {
	d, _ := New(128, 30*time.Millisecond)
	d.Seen([]byte("x"))
	time.Sleep(60 * time.Millisecond)
	if d.Seen([]byte("x")) {
		t.Fatal("entry should have expired")
	}
}
