//go:build !linux

package dataplane

func openKernelPolicy(kernelPolicyConfig) (kernelPolicyBackend, error) {
	return nil, errKernelPolicyPlatformUnsupported
}
