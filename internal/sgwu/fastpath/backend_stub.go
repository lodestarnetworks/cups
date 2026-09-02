//go:build !linux

package fastpath

import (
	"errors"

	"github.com/lodestarnetworks/cups/internal/sgwu/dataplane"
	"github.com/lodestarnetworks/cups/internal/sgwu/rules"
)

type Backend struct{}

func Open(Config, *rules.Store) (*Backend, error) {
	return nil, errors.New("sgwu fastpath: TCX is available only on Linux")
}

func (*Backend) Mode() string                         { return "unavailable" }
func (*Backend) Counters() dataplane.FastPathCounters { return dataplane.FastPathCounters{} }
func (*Backend) Usage() []dataplane.UsageMeasurement  { return nil }
func (*Backend) SessionChanged(uint64)                {}
func (*Backend) SessionDeleted(uint64)                {}
func (*Backend) Close() error                         { return nil }
