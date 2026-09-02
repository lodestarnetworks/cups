// lodestar-sbom emits a deterministic CycloneDX 1.6 SBOM from Go build
// metadata embedded in Lodestar release binaries.
package main

import (
	"crypto/sha256"
	debugbuildinfo "debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
)

type bom struct {
	Schema       string       `json:"$schema"`
	Format       string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber"`
	Version      int          `json:"version"`
	Metadata     metadata     `json:"metadata"`
	Components   []component  `json:"components"`
	Dependencies []dependency `json:"dependencies"`
}

type metadata struct {
	Tools     []tool    `json:"tools"`
	Component component `json:"component"`
}

type tool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type component struct {
	Type       string     `json:"type"`
	BOMRef     string     `json:"bom-ref"`
	Group      string     `json:"group,omitempty"`
	Name       string     `json:"name"`
	Version    string     `json:"version,omitempty"`
	PURL       string     `json:"purl,omitempty"`
	Hashes     []hash     `json:"hashes,omitempty"`
	Licenses   []license  `json:"licenses,omitempty"`
	Properties []property `json:"properties,omitempty"`
}

type hash struct {
	Algorithm string `json:"alg"`
	Content   string `json:"content"`
}

type license struct {
	Expression string `json:"expression"`
}

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

type binaryInfo struct {
	path       string
	name       string
	digest     string
	build      *debug.BuildInfo
	component  component
	moduleRefs []string
}

func main() {
	name := flag.String("name", "lodestar-cups", "release product name")
	version := flag.String("version", "dev", "release version")
	output := flag.String("output", "-", "output file, or - for stdout")
	flag.Parse()
	if err := run(*name, *version, *output, flag.Args()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(name, version, output string, binaries []string) error {
	name, version = strings.TrimSpace(name), strings.TrimSpace(version)
	if name == "" || version == "" || len(binaries) == 0 {
		return errors.New("name, version, and at least one release binary are required")
	}
	sort.Strings(binaries)
	infos := make([]binaryInfo, 0, len(binaries))
	moduleComponents := make(map[string]component)
	serialMaterial := name + "\x00" + version
	for _, path := range binaries {
		info, err := inspectBinary(path, version)
		if err != nil {
			return err
		}
		infos = append(infos, info)
		serialMaterial += "\x00" + info.name + "\x00" + info.digest
		for _, module := range modules(info.build) {
			component := moduleComponent(module)
			moduleComponents[component.BOMRef] = component
			info.moduleRefs = append(info.moduleRefs, component.BOMRef)
		}
		infos[len(infos)-1] = info
	}
	rootRef := fmt.Sprintf("pkg:generic/%s@%s", name, version)
	document := bom{
		Schema: "https://cyclonedx.org/schema/bom-1.6.schema.json", Format: "CycloneDX",
		SpecVersion: "1.6", SerialNumber: deterministicUUID(serialMaterial), Version: 1,
		Metadata: metadata{
			Tools: []tool{{Vendor: "Lodestar Networks", Name: "lodestar-sbom", Version: version}},
			Component: component{
				Type: "application", BOMRef: rootRef, Name: name, Version: version, PURL: rootRef,
				Licenses: []license{{Expression: "Apache-2.0"}},
			},
		},
	}
	rootDependencies := make([]string, 0, len(infos))
	for _, info := range infos {
		document.Components = append(document.Components, info.component)
		rootDependencies = append(rootDependencies, info.component.BOMRef)
		sort.Strings(info.moduleRefs)
		document.Dependencies = append(document.Dependencies, dependency{Ref: info.component.BOMRef, DependsOn: unique(info.moduleRefs)})
	}
	moduleRefs := make([]string, 0, len(moduleComponents))
	for ref := range moduleComponents {
		moduleRefs = append(moduleRefs, ref)
	}
	sort.Strings(moduleRefs)
	for _, ref := range moduleRefs {
		document.Components = append(document.Components, moduleComponents[ref])
		document.Dependencies = append(document.Dependencies, dependency{Ref: ref, DependsOn: []string{}})
	}
	sort.Slice(document.Components, func(left, right int) bool {
		return document.Components[left].BOMRef < document.Components[right].BOMRef
	})
	sort.Slice(document.Dependencies, func(left, right int) bool { return document.Dependencies[left].Ref < document.Dependencies[right].Ref })
	sort.Strings(rootDependencies)
	document.Dependencies = append([]dependency{{Ref: rootRef, DependsOn: rootDependencies}}, document.Dependencies...)
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return fmt.Errorf("encode SBOM: %w", err)
	}
	encoded = append(encoded, '\n')
	if output == "-" {
		_, err = os.Stdout.Write(encoded)
		return err
	}
	if err := os.WriteFile(output, encoded, 0o644); err != nil {
		return fmt.Errorf("write SBOM: %w", err)
	}
	return nil
}

func inspectBinary(path, releaseVersion string) (binaryInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return binaryInfo{}, fmt.Errorf("open release binary %s: %w", path, err)
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		_ = file.Close()
		return binaryInfo{}, fmt.Errorf("hash release binary %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return binaryInfo{}, err
	}
	build, err := debugbuildinfo.ReadFile(path)
	if err != nil {
		return binaryInfo{}, fmt.Errorf("read Go build metadata from %s: %w", path, err)
	}
	name := filepath.Base(path)
	ref := fmt.Sprintf("pkg:generic/lodestar-cups/%s@%s", name, releaseVersion)
	properties := []property{{Name: "lodestar:artifact:path", Value: "bin/" + name}, {Name: "golang:version", Value: build.GoVersion}}
	for _, setting := range build.Settings {
		if setting.Key == "GOOS" || setting.Key == "GOARCH" || setting.Key == "CGO_ENABLED" || setting.Key == "-buildmode" {
			properties = append(properties, property{Name: "golang:build:" + setting.Key, Value: setting.Value})
		}
	}
	sort.Slice(properties, func(left, right int) bool { return properties[left].Name < properties[right].Name })
	return binaryInfo{
		path: path, name: name, digest: hex.EncodeToString(digest.Sum(nil)), build: build,
		component: component{
			Type: "application", BOMRef: ref, Group: "uk.co.lodestarnetworks", Name: name,
			Version: releaseVersion, PURL: ref,
			Hashes: []hash{{Algorithm: "SHA-256", Content: hex.EncodeToString(digest.Sum(nil))}}, Properties: properties,
		},
	}, nil
}

func modules(build *debug.BuildInfo) []*debug.Module {
	out := make([]*debug.Module, 0, len(build.Deps)+1)
	if build.Main.Path != "" {
		main := build.Main
		out = append(out, &main)
	}
	out = append(out, build.Deps...)
	return out
}

func moduleComponent(module *debug.Module) component {
	effective := module
	properties := make([]property, 0, 2)
	if module.Replace != nil {
		effective = module.Replace
		properties = append(properties, property{Name: "golang:module:replaces", Value: module.Path + "@" + module.Version})
	}
	path := effective.Path
	if path == "" {
		path = module.Path
	}
	version := effective.Version
	if version == "" || version == "(devel)" {
		version = "devel"
	}
	if effective.Sum != "" {
		properties = append(properties, property{Name: "golang:module:sum", Value: effective.Sum})
	}
	sort.Slice(properties, func(left, right int) bool { return properties[left].Name < properties[right].Name })
	ref := "pkg:golang/" + path + "@" + version
	return component{Type: "library", BOMRef: ref, Name: path, Version: version, PURL: ref, Properties: properties}
}

func deterministicUUID(material string) string {
	digest := sha256.Sum256([]byte(material))
	value := digest[:16]
	value[6] = value[6]&0x0f | 0x50
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16])
}

func unique(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}
