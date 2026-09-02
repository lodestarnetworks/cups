package responsecache

import (
	"bytes"
	"testing"
	"time"
)

func TestCacheEvictsLeastRecentlyUsedInConstantSpace(t *testing.T) {
	cache := New[string](2, time.Minute)
	cache.Put("first", []byte{1})
	cache.Put("second", []byte{2})
	if _, ok := cache.Get("first"); !ok {
		t.Fatal("first response was not cached")
	}
	cache.Put("third", []byte{3})
	if _, ok := cache.Get("second"); ok {
		t.Fatal("least recently used response was not evicted")
	}
	if cache.Len() != 2 {
		t.Fatalf("cache length = %d, want 2", cache.Len())
	}
}

func TestCacheCopiesWireDataAndExpiresEntries(t *testing.T) {
	cache := New[string](1, time.Millisecond)
	wire := []byte{1, 2, 3}
	cache.Put("key", wire)
	wire[0] = 9
	got, ok := cache.Get("key")
	if !ok || !bytes.Equal(got, []byte{1, 2, 3}) {
		t.Fatalf("cached response = %v, found=%v", got, ok)
	}
	got[1] = 9
	again, ok := cache.Get("key")
	if !ok || !bytes.Equal(again, []byte{1, 2, 3}) {
		t.Fatalf("cache returned aliased data: %v, found=%v", again, ok)
	}
	time.Sleep(2 * time.Millisecond)
	if _, ok := cache.Get("key"); ok || cache.Len() != 0 {
		t.Fatal("expired response remained in the cache")
	}
}

func TestDisabledCacheNeverStoresResponses(t *testing.T) {
	for _, cache := range []*Cache[string]{New[string](0, time.Minute), New[string](1, 0)} {
		cache.Put("key", []byte{1})
		if _, ok := cache.Get("key"); ok || cache.Len() != 0 {
			t.Fatal("disabled cache stored a response")
		}
	}
}
