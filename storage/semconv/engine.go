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
	"errors"
	"fmt"
	"iter"
	"path"
	"slices"
	"strings"

	"github.com/prometheus/common/model"

	"github.com/prometheus/prometheus/model/labels"
)

// registrySource provides the raw bytes of registry files addressed by their
// registry/<name> path. The embedded registry (embed.FS) satisfies it directly;
// an operator-provided registry is adapted to it via newRegistrySource.
type registrySource interface {
	ReadFile(name string) ([]byte, error)
}

type schemaEngine struct {
	registry registrySource

	otelSchemaCache *staticCache[otelSchema]
	semconvCache    *staticCache[semconv]
}

func newSchemaEngine(registry registrySource) *schemaEngine {
	return &schemaEngine{
		registry:        registry,
		otelSchemaCache: newStaticCache[otelSchema](),
		semconvCache:    newStaticCache[semconv](),
	}
}

// metricLookup resolves what a semconv version declares for a metric name.
// declared reports whether that version declares the name as a metric at all;
// known reports whether the version's semconv could be consulted in the first
// place. A registry is not obliged to ship a semconv file for every version its
// schema references (see validateRegistryFiles), so known=false means "cannot
// verify" and must never be read as a contradiction.
type metricLookup func(version, name string) (def metricDef, declared, known bool)

// metricLookup returns a metricLookup that resolves sibling semconv versions
// from the same registry directory as semconvURL, e.g. registry/1.0.0 for
// version 1.0.0 when semconvURL is registry/1.1.0.
//
// This is where validating rename edges costs more than the current name-only
// traversal: answering one query can now touch a semconv file per version in
// the metric's rename chain rather than the anchor version alone. The per-call
// memo below collapses repeat lookups within a single query, and getSemconv's
// process-wide cache means each file is parsed at most once for the lifetime of
// the process, so the steady-state cost is the resident size of the versions
// actually queried rather than per-query I/O. It is still a real increase in
// the resolver's footprint, from the anchor version to O(versions in chain).
func (e *schemaEngine) metricLookup(semconvURL string) metricLookup {
	dir, _ := path.Split(semconvURL)
	// memo distinguishes "loaded" from "tried and failed" so an absent semconv
	// is not re-fetched for every hop that consults it.
	memo := map[string]*semconv{}
	return func(version, name string) (metricDef, bool, bool) {
		sc, tried := memo[version]
		if !tried {
			if loaded, err := e.getSemconv(dir + version); err == nil {
				sc = &loaded
			}
			memo[version] = sc
		}
		if sc == nil {
			return metricDef{}, false, false
		}
		def, declared := sc.metrics[name]
		return def, declared, true
	}
}

// renameValidator corroborates the schema's metric rename edges against the
// semconv files of the versions they connect.
//
// The OTel schema format names metrics only by their surface name, so the rename
// graph alone cannot distinguish a genuine rename of one metric from an edge
// that happens to join two unrelated metrics sharing a name at different
// versions. The semconv files can: each version states the unit and instrument
// of the metric it declares under that name, and upstream semantic conventions
// forbid a stable metric from changing either (policies/compatibility.rego). A
// disagreement across an edge therefore means the two names denote different
// metrics.
//
// A group's id is of no use here even though it looks like a stable identifier:
// upstream lints it to be exactly "metric.<metric_name>"
// (policies/yaml_schema.rego), so it is renamed in lockstep with the metric and
// comparing ids across an edge only restates whether the name changed.
type renameValidator struct {
	schema *otelSchema
	lookup metricLookup

	warnings []string
	seen     map[string]struct{}
}

func newRenameValidator(schema *otelSchema, lookup metricLookup) *renameValidator {
	return &renameValidator{schema: schema, lookup: lookup, seen: map[string]struct{}{}}
}

func (rv *renameValidator) warn(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if _, dup := rv.seen[msg]; dup {
		return
	}
	rv.seen[msg] = struct{}{}
	rv.warnings = append(rv.warnings, msg)
}

// allowEdge reports whether the walk may traverse version r's renames starting
// from metric name from. A nil validator allows everything, which is the
// behaviour when no semconv is available to check against.
//
// It rejects an edge only on positive contradiction — both endpoints declared,
// but with a different unit or instrument — because fusing metrics measured in
// different units yields numerically meaningless results, which is worse than
// returning less data. Every other suspicious case is reported and still
// traversed: a name missing from a version's semconv is a strong hint of a
// mis-authored edge, but a registry may legitimately ship a semconv trimmed to
// the metrics its operator cares about, and dropping variants over that would
// lose real series.
func (rv *renameValidator) allowEdge(r versionRenames, from string) bool {
	if rv == nil {
		return true
	}
	older, newer, ok := r.renameDirection(from)
	if !ok {
		// An attribute-only hop renames no metric, so there is no metric
		// identity to corroborate.
		return true
	}
	predecessor, hasPredecessor := rv.schema.predecessorOf(r.version)
	if !hasPredecessor {
		// The rename is recorded at the schema's earliest version, so the
		// version the older name belonged to is outside the schema's history.
		return true
	}

	oldDef, oldDeclared, oldKnown := rv.lookup(predecessor, older)
	newDef, newDeclared, newKnown := rv.lookup(r.version, newer)
	if !oldKnown || !newKnown {
		return true
	}

	switch {
	case !oldDeclared && !newDeclared:
		rv.warn("schema version %s renames %q to %q but neither name is declared as a metric by semconv %s or %s; the rename could not be corroborated",
			r.version, older, newer, predecessor, r.version)
	case !oldDeclared:
		rv.warn("schema version %s renames %q to %q but semconv %s does not declare %q as a metric; the rename could not be corroborated",
			r.version, older, newer, predecessor, older)
	case !newDeclared:
		rv.warn("schema version %s renames %q to %q but semconv %s does not declare %q as a metric; the rename could not be corroborated",
			r.version, older, newer, r.version, newer)
	case !oldDef.sameMetricAs(newDef):
		rv.warn("schema version %s renames %q to %q but semconv %s declares %q as %s/%s while semconv %s declares %q as %s/%s; treating them as different metrics and not merging their series",
			r.version, older, newer,
			predecessor, older, describeUnit(oldDef.unit), describeUnit(oldDef.instrument),
			r.version, newer, describeUnit(newDef.unit), describeUnit(newDef.instrument))
		return false
	}
	return true
}

// describeUnit renders a unit or instrument for a warning message, naming an
// undeclared one rather than rendering it as an empty string.
func describeUnit(s string) string {
	if s == "" {
		return "(unspecified)"
	}
	return s
}

func extractMetricName(matchers []*labels.Matcher) (string, error) {
	for _, m := range matchers {
		if m.Name == model.MetricNameLabel {
			if m.Type != labels.MatchEqual {
				return "", errors.New("__name__ matcher must be equal")
			}
			return m.Value, nil
		}
	}
	return "", nil
}

// findVersionAnchorIndex returns the index of the largest version <= targetVersion.
// The versions slice must be sorted in ascending semver order.
func findVersionAnchorIndex(versions []versionRenames, targetVersion string) int {
	target := strings.TrimPrefix(targetVersion, "v")
	anchorIdx := 0
	for i, v := range versions {
		if compareSemver(v.version, target) > 0 {
			break
		}
		anchorIdx = i
	}
	return anchorIdx
}

// generateMatcherVariants generates matcher sets for schema version renames,
// anchored at the specified version.
// For each version, applies both metric and attribute renames together.
// Walks backward through versions <= version to find older name variants,
// and forward through versions > version to find newer name variants.
// rv corroborates each metric rename against the semconv files of the versions
// it connects; a nil rv skips that check and traverses the graph on name
// matching alone.
func generateMatcherVariants(version string, schema *otelSchema, matchers []*labels.Matcher, rv *renameValidator) [][]*labels.Matcher {
	if len(schema.versionRenames) == 0 {
		return [][]*labels.Matcher{matchers}
	}

	variants := [][]*labels.Matcher{matchers}
	seen := map[string]struct{}{matcherKey(matchers): {}}
	anchorIdx := findVersionAnchorIndex(schema.versionRenames, version)

	// Backward for older names.
	variants = walkVersions(schema.versionRenames[:anchorIdx+1], matchers, seen, variants, true, rv)

	// Forward for newer names.
	variants = walkVersions(schema.versionRenames[anchorIdx+1:], matchers, seen, variants, false, rv)

	return variants
}

// walkVersions walks through versions applying renames, chaining results until no new variants.
// If reverse is false, walks oldest→newest; if true, walks newest→oldest.
func walkVersions(
	versions []versionRenames,
	matchers []*labels.Matcher,
	seen map[string]struct{},
	result [][]*labels.Matcher,
	reverse bool,
	rv *renameValidator,
) [][]*labels.Matcher {
	current := matchers
	for {
		found := false
		var versionsIter iter.Seq2[int, versionRenames]
		if reverse {
			versionsIter = slices.Backward(versions)
		} else {
			versionsIter = slices.All(versions)
		}

		for _, v := range versionsIter {
			currentName, err := extractMetricName(current)
			if err == nil && !rv.allowEdge(v, currentName) {
				// The semconv files contradict this rename, so the walk must
				// not chain through it either: anything reachable only via a
				// mis-linked edge belongs to a different metric.
				continue
			}
			transformed := applyVersionRenames(current, v)
			if transformed == nil {
				continue
			}

			key := matcherKey(transformed)
			if _, exists := seen[key]; exists {
				continue
			}

			seen[key] = struct{}{}
			result = append(result, transformed)
			current = transformed
			found = true
			break
		}
		if !found {
			break
		}
	}
	return result
}

// buildAttributeRenameMap returns a map from each historical or forward
// attribute alias to its name at anchorVersion, for the attributes in
// canonicalAttrs (the metric's attributes declared by the anchor semconv
// version). It is anchored and walked exactly like generateMatcherVariants
// (backward over versions <= anchor, forward over versions > anchor), so every
// alias a returned series can carry maps back to the queried version's name.
// Identity entries (alias == canonical) are omitted; it returns nil when the
// schema renames none of the attributes.
func buildAttributeRenameMap(anchorVersion string, schema *otelSchema, canonicalAttrs []string) map[string]string {
	if len(schema.versionRenames) == 0 || len(canonicalAttrs) == 0 {
		return nil
	}
	anchorIdx := findVersionAnchorIndex(schema.versionRenames, anchorVersion)
	backward := schema.versionRenames[:anchorIdx+1]
	forward := schema.versionRenames[anchorIdx+1:]

	out := map[string]string{}
	for _, canon := range canonicalAttrs {
		walkAttributeRenames(backward, canon, true, out)
		walkAttributeRenames(forward, canon, false, out)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// walkAttributeRenames threads canon through the versions' attribute renames,
// recording each distinct produced alias → canon in out. With reverse=true it
// walks newest→oldest, otherwise oldest→newest, chaining via a per-canon seen
// set — mirroring walkVersions so the attribute walk stays consistent with the
// matcher fan-out.
func walkAttributeRenames(versions []versionRenames, canon string, reverse bool, out map[string]string) {
	current := canon
	seen := map[string]struct{}{canon: {}}
	for {
		found := false
		var versionsIter iter.Seq2[int, versionRenames]
		if reverse {
			versionsIter = slices.Backward(versions)
		} else {
			versionsIter = slices.All(versions)
		}

		for _, v := range versionsIter {
			next, ok := v.attributes[current]
			if !ok {
				continue
			}
			if _, exists := seen[next]; exists {
				continue
			}
			seen[next] = struct{}{}
			out[next] = canon
			current = next
			found = true
			break
		}
		if !found {
			break
		}
	}
}

// matcherKey generates a string key for a matcher set to detect duplicates.
func matcherKey(matchers []*labels.Matcher) string {
	var b strings.Builder
	for i, m := range matchers {
		if i > 0 {
			b.WriteByte('|')
		}
		b.WriteString(m.Name)
		b.WriteByte('=')
		b.WriteString(m.Value)
	}
	return b.String()
}

// applyVersionRenames applies a version's metric and attribute renames to matchers.
// Returns nil if no renames apply. Uses lazy allocation to avoid allocating when no changes are made.
func applyVersionRenames(matchers []*labels.Matcher, renames versionRenames) []*labels.Matcher {
	var result []*labels.Matcher
	for i, m := range matchers {
		var newMatcher *labels.Matcher
		if m.Name == model.MetricNameLabel {
			if variant, ok := renames.metrics[m.Value]; ok {
				newMatcher = labels.MustNewMatcher(m.Type, m.Name, variant)
			}
		} else if variant, ok := renames.attributes[m.Name]; ok {
			newMatcher = labels.MustNewMatcher(m.Type, variant, m.Value)
		}
		if newMatcher != nil {
			if result == nil {
				// Lazy allocate and copy preceding unchanged matchers.
				result = make([]*labels.Matcher, len(matchers))
				copy(result[:i], matchers[:i])
			}
			result[i] = newMatcher
		} else if result != nil {
			result[i] = m
		}
	}

	return result
}

type queryContext struct {
	// labelMapping is a mapping to the requested OTel semantic conventions version.
	labelMapping *labelMapping

	// warnings holds problems found while resolving the query that do not stop
	// it from being answered, but do mean the answer may fuse or omit series:
	// an ambiguously declared metric name, or a schema rename edge that the
	// semconv files contradict. They are surfaced through Warnings() so a user
	// is told the result is suspect instead of silently trusting it.
	warnings []string
}

// getSemconv returns the semconv parsed from url, fetching it via the
// embedded registry on a cache miss.
func (e *schemaEngine) getSemconv(url string) (semconv, error) {
	if sc, ok := e.semconvCache.get(url); ok {
		return sc, nil
	}
	sc, err := e.fetchSemconv(url)
	if err != nil {
		return semconv{}, err
	}
	e.semconvCache.set(url, sc)
	return sc, nil
}

// getOTelSchema returns the OTel schema parsed from url, fetching it via the
// embedded registry on a cache miss.
func (e *schemaEngine) getOTelSchema(url string) (otelSchema, error) {
	if s, ok := e.otelSchemaCache.get(url); ok {
		return s, nil
	}
	s, err := e.fetchOTelSchema(url)
	if err != nil {
		return otelSchema{}, err
	}
	e.otelSchemaCache.set(url, s)
	return s, nil
}

// findMatcherVariants returns all variants to match for a single schematized
// metric selection. semconvURL points to a semantic conventions file and is
// always required. In production schemaURL (an OTel schema file with versioned
// renames) is also always set, because classifyMatchers only triggers fan-out
// when both are present; the empty-schemaURL path exists only for the direct
// unit test. It returns one variant per schema-version rename of the metric,
// plus a label mapping for transforming results back to the requested version.
// The returned matchers do not include the reserved schema matchers. It returns
// an error if semconvURL is not provided.
func (e *schemaEngine) findMatcherVariants(semconvURL, schemaURL string, originalMatchers []*labels.Matcher) ([][]*labels.Matcher, queryContext, error) {
	if semconvURL == "" {
		return nil, queryContext{}, errors.New("semconvURL is required")
	}

	// Filter out the wrapper's reserved matchers.
	matchers := stripReservedLabels(originalMatchers)

	// Fetch semantic conventions for the anchor version (also validates the URL).
	sc, err := e.getSemconv(semconvURL)
	if err != nil {
		return nil, queryContext{}, err
	}

	metricName, err := extractMetricName(matchers)
	if err != nil {
		return nil, queryContext{}, err
	}
	if metricName == "" {
		// Without an explicit __name__ matcher we have no anchor to resolve
		// renames against; fall through to the underlying querier without
		// applying any rewrite.
		return [][]*labels.Matcher{matchers}, queryContext{}, nil
	}

	var warnings []string
	if slices.Contains(sc.ambiguousMetrics, metricName) {
		warnings = append(warnings, fmt.Sprintf(
			"metric %q is declared by more than one group in semconv %s; its attributes and unit are ambiguous and results may fuse distinct metrics",
			metricName, sc.version))
	}

	// Generate schema-version rename variants. In production schemaURL is always
	// set (classifyMatchers gates fan-out on it); the empty case is reached only
	// by direct unit tests and falls through to the unmodified matchers.
	allVariants := [][]*labels.Matcher{matchers}
	var attrRenames map[string]string
	if schemaURL != "" {
		schema, err := e.getOTelSchema(schemaURL)
		if err != nil {
			return nil, queryContext{}, err
		}
		// Corroborate each rename against the semconv of the versions it
		// connects, so a schema edge that joins two unrelated metrics sharing a
		// surface name is reported rather than silently merged.
		rv := newRenameValidator(&schema, e.metricLookup(semconvURL))
		allVariants = generateMatcherVariants(sc.version, &schema, matchers, rv)
		warnings = append(warnings, rv.warnings...)
		// Map each historical attribute alias back to its anchor-version name so
		// results from older or newer eras merge under the queried version's
		// labels instead of splitting on the renamed attribute. Recomputed per
		// query on purpose: it is a pure function of the cached schema/semconv and
		// costs only a few map ops, far less than the fan-out it feeds.
		attrRenames = buildAttributeRenameMap(sc.version, &schema, sc.attributesOf(metricName))
	}

	return allVariants, queryContext{
		labelMapping: buildLabelMapping(metricName, attrRenames),
		warnings:     warnings,
	}, nil
}

// transformSeries returns the series labels rewritten to the canonical OTel
// semantic convention names recorded in q.labelMapping. When no mapping
// applies, any stray __schema_url__ label is stripped and the labels are
// returned otherwise unchanged.
func (*schemaEngine) transformSeries(q queryContext, originalLabels labels.Labels) labels.Labels {
	if q.labelMapping != nil {
		return transformOTelSchemaLabels(originalLabels, q.labelMapping)
	}
	if originalLabels.Get(schemaURLLabel) == "" {
		return originalLabels
	}
	builder := labels.NewBuilder(originalLabels)
	builder.Del(schemaURLLabel)
	return builder.Labels()
}

// labelMapping rewrites a returned series' names to the queried semantic-
// conventions version: translatedMetric is the queried (anchor) metric name
// that every variant collapses to, and translatedLabels maps each historical
// attribute alias back to its anchor-version name.
type labelMapping struct {
	translatedLabels map[string]string // historical attribute alias → anchor name, e.g. "user" -> "tenant"
	translatedMetric string
}

// buildLabelMapping creates the mapping used to rewrite result labels back to
// the requested semantic-conventions version: the result metric name maps to
// the queried (anchor) name, and translatedLabels maps each historical
// attribute alias back to its anchor-version name (nil/empty when no attribute
// was renamed).
func buildLabelMapping(metricName string, translatedLabels map[string]string) *labelMapping {
	return &labelMapping{translatedMetric: metricName, translatedLabels: translatedLabels}
}

// aliasesOf returns name together with every historical alias that maps to it,
// i.e. the set of label names a returned series may carry for the canonical
// name. It is the inverse of translatedLabels and is used to fan LabelValues
// out across a renamed attribute's historical names. The metric name has no
// attribute aliases, so it is returned unchanged.
func (m *labelMapping) aliasesOf(name string) []string {
	aliases := []string{name}
	for alias, canonical := range m.translatedLabels {
		if canonical == name {
			aliases = append(aliases, alias)
		}
	}
	return aliases
}

// transformOTelSchemaLabels transforms series labels to the current semantic conventions version
// using the label mapping.
func transformOTelSchemaLabels(originalLabels labels.Labels, mapping *labelMapping) labels.Labels {
	builder := labels.NewScratchBuilder(originalLabels.Len())
	originalLabels.Range(func(l labels.Label) {
		switch l.Name {
		case semconvURLLabel, schemaURLLabel:
			// Skip.
		case model.MetricNameLabel:
			builder.Add(l.Name, mapping.translatedMetric)
		default:
			if originalName, ok := mapping.translatedLabels[l.Name]; ok {
				builder.Add(originalName, l.Value)
			} else {
				builder.Add(l.Name, l.Value)
			}
		}
	})
	return builder.Labels()
}
