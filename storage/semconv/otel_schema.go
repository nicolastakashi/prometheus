// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package semconv

import (
	"embed"
	"fmt"
	"maps"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/grafana/regexp"
	"go.yaml.in/yaml/v3"
)

// embeddedRegistry holds the bundled semconv and OTel schema files served as
// the default source from which __semconv_url__ and __schema_url__ values are
// resolved. Operators may replace it with their own registry via configuration
// (see AwareStorageWithRegistry); either way, queries can only ever name files
// inside the registry namespace. Accepting arbitrary HTTP URLs or local
// filesystem paths from the matchers themselves would expose a server-side
// fetch primitive to anyone able to issue a PromQL query, which is why the
// matcher values are gated by registryURLRe rather than treated as locations.
//
//go:embed registry/*
var embeddedRegistry embed.FS

// registryURLRe matches the only accepted shape of __semconv_url__ /
// __schema_url__ values: a single non-empty path segment under registry/.
// Path traversal (..) and absolute paths are rejected.
var registryURLRe = regexp.MustCompile(`^registry/[^/.][^/]*$`)

// semverRe matches plain MAJOR.MINOR.PATCH version strings. Pre-release and
// build metadata are intentionally not accepted; semconv versions in the
// registry are plain dotted integers.
var semverRe = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// validateSemver returns an error if v is not a plain MAJOR.MINOR.PATCH string.
func validateSemver(v string) error {
	if !semverRe.MatchString(v) {
		return fmt.Errorf("invalid semver %q: expected MAJOR.MINOR.PATCH", v)
	}
	return nil
}

// semconv represents a semantic conventions file containing metric definitions.
// See: https://github.com/open-telemetry/semantic-conventions
//
// Example semconv YAML:
//
//	groups:
//	  - id: metric.http.server.duration
//	    type: metric
//	    metric_name: http.server.duration
//	    instrument: histogram
//	    unit: s
type semconv struct {
	Groups []semconvGroup `yaml:"groups"`

	version string

	// metrics indexes this version's metric groups by their metric_name
	// (populated by loadSemconv). It answers both "is this name a metric at this
	// version" and "what does it declare", which is what validating a schema
	// rename edge needs; see validateMetricRename.
	metrics map[string]metricDef

	// ambiguousMetrics lists metric names declared by more than one group at
	// this version, sorted. Such a name has no single definition, so anything
	// resolved through it is unreliable and is reported to the caller rather
	// than silently resolved to whichever group happened to be parsed last.
	ambiguousMetrics []string
}

// metricDef is the part of a semconv metric group that describes what the metric
// *is*, as opposed to what it is currently called. unit and instrument are the
// fields upstream semantic conventions forbid a stable metric from changing (see
// policies/compatibility.rego in open-telemetry/semantic-conventions), which is
// what makes them usable as a cross-version identity check.
//
// Note that a group's id is deliberately not part of this: upstream lints id to
// be exactly "metric.<metric_name>" (policies/yaml_schema.rego), so it is a pure
// function of the surface name and changes in lockstep with every rename. It
// therefore carries no identity information a rename edge does not already have.
type metricDef struct {
	unit       string
	instrument string
	attributes []string
}

// sameMetricAs reports whether d and other are compatible enough to be the same
// semantic metric across a rename. A differing unit or instrument means two
// distinct metrics that merely share a surface name at different versions.
func (d metricDef) sameMetricAs(other metricDef) bool {
	return d.unit == other.unit && d.instrument == other.instrument
}

// attributesOf returns the attributes the named metric declares at this semconv
// version, or nil if the name is not a metric here.
func (s semconv) attributesOf(name string) []string {
	return s.metrics[name].attributes
}

// otelSchema represents an OpenTelemetry schema file.
// See: https://opentelemetry.io/docs/specs/otel/schemas/file_format_v1.1.0/
//
// Example schema YAML:
//
//	file_format: 1.1.0
//	schema_url: https://example.com/schemas/1.0.0
//
//	versions:
//	  1.0.0:
//	    metrics:
//	      changes:
//	        - rename_attributes:
//	            attribute_map:
//	              http.method: http.request.method
//	            apply_to_metrics:
//	              - http.server.duration
type otelSchema struct {
	FileFormat string                       `yaml:"file_format"`
	SchemaURL  string                       `yaml:"schema_url"`
	Versions   map[string]otelSchemaVersion `yaml:"versions"`

	// versionRenames holds per-version renames for generating matcher variants
	// (populated by loadOTelSchema). Versions that rename nothing are omitted.
	versionRenames []versionRenames

	// allVersions lists every version the schema declares, in ascending semver
	// order, including versions that rename nothing (populated by
	// loadOTelSchema). Unlike versionRenames it is a complete history, which is
	// what identifying the version a pre-rename name belongs to requires: a
	// rename recorded under version V takes effect at V, so the old name is the
	// current one at V's immediate predecessor here, which may well be a version
	// that renames nothing.
	allVersions []string
}

// predecessorOf returns the version immediately before v in the schema's version
// history, and false if v is the earliest version or is not in the history.
func (s *otelSchema) predecessorOf(v string) (string, bool) {
	for i, have := range s.allVersions {
		if have == v {
			if i == 0 {
				return "", false
			}
			return s.allVersions[i-1], true
		}
	}
	return "", false
}

// versionRenames holds bidirectional rename mappings from a single schema version.
// When a version renames a→b, both directions are stored for lookup.
type versionRenames struct {
	version    string            // e.g., "1.1.0"
	metrics    map[string]string // metric name → its variant (bidirectional)
	attributes map[string]string // attribute name → its variant (bidirectional)

	// metricsForward holds metric renames in the direction the schema declares
	// them, old name → new name. metrics is deliberately bidirectional so a walk
	// can traverse an edge from either end, but that loses which end is the older
	// name, and validating an edge against the semconv files requires knowing
	// which version each name belongs to.
	metricsForward map[string]string
}

// renameDirection reports the older and newer name of the metric rename edge
// connecting from to its variant at this version, and false if from is not
// renamed here.
func (r versionRenames) renameDirection(from string) (older, newer string, ok bool) {
	to, ok := r.metrics[from]
	if !ok {
		return "", "", false
	}
	if _, forward := r.metricsForward[from]; forward {
		return from, to, true
	}
	return to, from, true
}

// collectVersionRenames extracts bidirectional rename mappings from a schema version.
func collectVersionRenames(versionStr string, version otelSchemaVersion) *versionRenames {
	renames := &versionRenames{
		version:        versionStr,
		metrics:        make(map[string]string),
		attributes:     make(map[string]string),
		metricsForward: make(map[string]string),
	}

	// Collect attribute renames from "all" section.
	if version.All != nil {
		for _, change := range version.All.Changes {
			if change.RenameAttributes != nil {
				for oldName, newName := range change.RenameAttributes.AttributeMap {
					renames.attributes[oldName] = newName
					renames.attributes[newName] = oldName
				}
			}
		}
	}

	// Collect metric and attribute renames from "metrics" section.
	if version.Metrics != nil {
		for _, change := range version.Metrics.Changes {
			if change.RenameMetrics != nil {
				for oldName, newName := range change.RenameMetrics.NameMap {
					renames.metrics[oldName] = newName
					renames.metrics[newName] = oldName
					renames.metricsForward[oldName] = newName
				}
			}
			if change.RenameAttributes != nil {
				for oldName, newName := range change.RenameAttributes.AttributeMap {
					renames.attributes[oldName] = newName
					renames.attributes[newName] = oldName
				}
			}
		}
	}

	if len(renames.metrics) == 0 && len(renames.attributes) == 0 {
		return nil
	}
	return renames
}

// semconvGroup represents a semantic conventions group definition.
type semconvGroup struct {
	ID         string             `yaml:"id"`
	Type       string             `yaml:"type"`        // "metric", "attribute", "span", etc.
	MetricName string             `yaml:"metric_name"` // Only for type="metric"
	Unit       string             `yaml:"unit"`        // Only for type="metric", e.g. "s", "By"
	Instrument string             `yaml:"instrument"`  // Only for type="metric", e.g. "histogram", "counter"
	Attributes []semconvAttribute `yaml:"attributes,omitempty"`
}

type semconvAttribute struct {
	// Ref to attribute ID.
	Ref string `yaml:"ref"`
}

type otelSchemaVersion struct {
	All     *otelSchemaSection `yaml:"all,omitempty"`
	Metrics *otelSchemaSection `yaml:"metrics,omitempty"`
}

type otelSchemaSection struct {
	Changes []otelSchemaChange `yaml:"changes,omitempty"`
}

type otelSchemaChange struct {
	RenameAttributes *otelRenameAttributes `yaml:"rename_attributes,omitempty"`
	RenameMetrics    *otelRenameMetrics    `yaml:"rename_metrics,omitempty"`
}

type otelRenameAttributes struct {
	AttributeMap   map[string]string `yaml:"attribute_map,omitempty"`
	ApplyToMetrics []string          `yaml:"apply_to_metrics,omitempty"`
}

type otelRenameMetrics struct {
	NameMap map[string]string `yaml:"name_map,omitempty"`
}

// staticCache is a generic, goroutine-safe cache keyed by URL for static
// (immutable, bounded) values. Entries never expire and are not evicted:
// the resolver only accepts paths inside the embedded registry, whose
// contents are bounded and immutable, so TTL- and size-based eviction would
// only add complexity for no benefit. Two callers racing on a cold key may
// both invoke the loader and Store the same value; the result is identical
// either way.
type staticCache[T any] struct {
	m sync.Map // url → T
}

func newStaticCache[T any]() *staticCache[T] {
	return &staticCache[T]{}
}

func (c *staticCache[T]) get(url string) (T, bool) {
	v, ok := c.m.Load(url)
	if !ok {
		var zero T
		return zero, false
	}
	return v.(T), true
}

func (c *staticCache[T]) set(url string, value T) {
	c.m.Store(url, value)
}

// fetchOTelSchema reads an OTel schema file from the engine's registry source
// and parses it. The URL must satisfy registryURLRe.
func (e *schemaEngine) fetchOTelSchema(url string) (otelSchema, error) {
	b, err := e.readRegistryFile(url)
	if err != nil {
		return otelSchema{}, fmt.Errorf("fetch OTel schema %q: %w", url, err)
	}
	s, err := loadOTelSchema(b)
	if err != nil {
		return otelSchema{}, fmt.Errorf("parse OTel schema %q: %w", url, err)
	}
	return s, nil
}

// loadOTelSchema parses raw OTel schema YAML bytes and post-processes them
// (validates file_format and per-version semver, collects attribute renames,
// sorts versions). It is the YAML-parsing core of fetchOTelSchema and is
// directly callable from tests that load fixtures off disk.
func loadOTelSchema(b []byte) (otelSchema, error) {
	var s otelSchema
	if err := yaml.Unmarshal(b, &s); err != nil {
		return otelSchema{}, fmt.Errorf("unmarshal: %w", err)
	}
	if s.FileFormat != "1.1.0" && s.FileFormat != "1.0.0" {
		return otelSchema{}, fmt.Errorf("unsupported OTel schema file format %q (expected 1.0.0 or 1.1.0)", s.FileFormat)
	}

	s.versionRenames = make([]versionRenames, 0, len(s.Versions))
	s.allVersions = make([]string, 0, len(s.Versions))

	for versionStr, version := range s.Versions {
		if err := validateSemver(versionStr); err != nil {
			return otelSchema{}, err
		}
		s.allVersions = append(s.allVersions, versionStr)
		if renames := collectVersionRenames(versionStr, version); renames != nil {
			s.versionRenames = append(s.versionRenames, *renames)
		}
	}

	slices.SortFunc(s.versionRenames, func(a, b versionRenames) int {
		return compareSemver(a.version, b.version)
	})
	slices.SortFunc(s.allVersions, compareSemver)

	return s, nil
}

// compareSemver compares two MAJOR.MINOR.PATCH version strings.
// Returns -1 if a < b, 0 if a == b, 1 if a > b. Both inputs must have
// already passed validateSemver; otherwise behaviour is undefined.
func compareSemver(a, b string) int {
	partsA := strings.Split(a, ".")
	partsB := strings.Split(b, ".")
	for i := range partsA {
		numA, _ := strconv.Atoi(partsA[i])
		numB, _ := strconv.Atoi(partsB[i])
		if numA != numB {
			if numA < numB {
				return -1
			}
			return 1
		}
	}
	return 0
}

// fetchSemconv reads a semconv file from the engine's registry source and parses
// it. The version is derived from the last path segment of url; the URL must
// satisfy registryURLRe and the derived version must satisfy validateSemver.
func (e *schemaEngine) fetchSemconv(url string) (semconv, error) {
	b, err := e.readRegistryFile(url)
	if err != nil {
		return semconv{}, fmt.Errorf("fetch semconv %q: %w", url, err)
	}
	_, version := path.Split(url)
	s, err := loadSemconv(b, version)
	if err != nil {
		return semconv{}, fmt.Errorf("parse semconv %q: %w", url, err)
	}
	return s, nil
}

// loadSemconv parses raw semconv YAML bytes and post-processes them. The
// version is supplied by the caller (semconv files do not record their own
// version inside the YAML) and must satisfy validateSemver.
func loadSemconv(b []byte, version string) (semconv, error) {
	if err := validateSemver(version); err != nil {
		return semconv{}, err
	}
	var s semconv
	if err := yaml.Unmarshal(b, &s); err != nil {
		return semconv{}, fmt.Errorf("unmarshal: %w", err)
	}
	s.version = version
	s.metrics = make(map[string]metricDef)
	// A metric name declared by two groups has no single definition. Keeping the
	// first declaration rather than the last makes the outcome depend on file
	// order in one direction only, but either choice is arbitrary, so the name is
	// also recorded as ambiguous and reported to the querier as a warning.
	var ambiguous map[string]struct{}
	for _, group := range s.Groups {
		if group.Type != "metric" || group.MetricName == "" {
			continue
		}
		if _, dup := s.metrics[group.MetricName]; dup {
			if ambiguous == nil {
				ambiguous = map[string]struct{}{}
			}
			ambiguous[group.MetricName] = struct{}{}
			continue
		}
		var attrs []string
		if len(group.Attributes) > 0 {
			attrs = make([]string, 0, len(group.Attributes))
			for _, attr := range group.Attributes {
				attrs = append(attrs, attr.Ref)
			}
		}
		s.metrics[group.MetricName] = metricDef{
			unit:       group.Unit,
			instrument: group.Instrument,
			attributes: attrs,
		}
	}
	if len(ambiguous) > 0 {
		s.ambiguousMetrics = slices.Sorted(maps.Keys(ambiguous))
	}
	return s, nil
}

// readRegistryFile reads a file from the engine's registry source. The path must
// satisfy registryURLRe — HTTP URLs and arbitrary local files are rejected to
// keep the __semconv_url__/__schema_url__ matchers from acting as a server-side
// fetch primitive. The gate applies to every source, embedded or operator-provided.
func (e *schemaEngine) readRegistryFile(url string) ([]byte, error) {
	if !registryURLRe.MatchString(url) {
		return nil, fmt.Errorf("invalid registry URL %q: only registry paths (registry/<name>) are accepted", url)
	}
	b, err := e.registry.ReadFile(url)
	if err != nil {
		return nil, fmt.Errorf("read registry file %s: %w", url, err)
	}
	return b, nil
}
