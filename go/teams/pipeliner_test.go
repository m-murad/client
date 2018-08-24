package teams

import (
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
	"math/rand"
	"sync"
	"testing"
	"time"
)

func TestPipeliner(t *testing.T) {
	v, err := testPipeliner()
	require.NoError(t, err)
	for i, e := range v {
		require.Equal(t, i, e)
	}
}

func testPipeliner() ([]int, error) {
	v := make([]int, 100)
	var vlock sync.Mutex
	ctx := context.Background()
	pipeliner := NewPipeliner(4)

	f := func(ctx context.Context, i int, cb func(e error)) {
		vlock.Lock()
		v[i] = i
		vlock.Unlock()
		time.Sleep(time.Millisecond * time.Duration((rand.Int() % 17)))
		cb(nil)
	}

	for i := range v {
		err := pipeliner.WaitForRoom(ctx)
		if err != nil {
			return nil, err
		}
		go f(ctx, i, func(e error) { pipeliner.CompleteOne(e) })
	}
	err := pipeliner.Flush(ctx)
	return v, err
}
