//go:build !linux

package kernelgtp

import "net/netip"

type Controller struct{}

func Open() (*Controller, error)                          { return nil, ErrUnsupported }
func (c *Controller) Close() error                        { return nil }
func (c *Controller) CreateLink(LinkConfig) (Link, error) { return Link{}, ErrUnsupported }
func (c *Controller) InspectLink(string) (Link, error)    { return Link{}, ErrUnsupported }
func (c *Controller) DeleteLink(string) error             { return ErrUnsupported }
func (c *Controller) ConfigureIPv4(Link, netip.Addr, netip.Prefix) error {
	return ErrUnsupported
}
func (c *Controller) ConfigurePolicyIPv4(Link, netip.Prefix, PolicyRoutingConfig) (RecoveryReport, error) {
	return RecoveryReport{}, ErrUnsupported
}
func (c *Controller) ConfigurePolicyIPv4Prefixes(Link, []netip.Prefix, PolicyRoutingConfig) (RecoveryReport, error) {
	return RecoveryReport{}, ErrUnsupported
}
func (c *Controller) PeerFilterCounters(Link) (PeerFilterCounters, error) {
	return PeerFilterCounters{}, ErrUnsupported
}
func (c *Controller) AddContext(Context) error                   { return ErrUnsupported }
func (c *Controller) EnsureContext(Context) (bool, error)        { return false, ErrUnsupported }
func (c *Controller) DeleteContext(uint32, uint32) error         { return ErrUnsupported }
func (c *Controller) GetContext(uint32, uint32) (Context, error) { return Context{}, ErrUnsupported }
func (c *Controller) ListContexts(uint32) ([]Context, error)     { return nil, ErrUnsupported }
func (c *Controller) Reconcile(uint32, []Context) (ReconcileReport, error) {
	return ReconcileReport{}, ErrUnsupported
}
