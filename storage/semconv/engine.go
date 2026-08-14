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
// Checks are made against the metric the query asked for — the anchor — and not
// between an edge's own two endpoints. A metric name that was renamed away is
// free to be reused later by an unrelated metric, and an edge describing that
// earlier rename is perfectly self-consistent while having nothing to do with the
// metric now carrying the name. Only comparing each hop back to the anchor
// catches that, which is the case the schema format cannot express at all.
type renameValidator struct {
	schema *otelSchema
	lookup metricLookup

	// anchorName/anchorVersion/anchorDef describe the metric the query asked for.
	// anchorVersion is the queried semconv version where it declares the name, and
	// otherwise the version the identity was recovered from; see
	// identityFromOwnEra. anchorKnown is false only when no version settles what
	// the name denotes, leaving no identity to compare hops against.
	anchorName    string
	anchorVersion string
	anchorDef     metricDef
	anchorKnown   bool

	warnings []string
	seen     map[string]struct{}
}

func newRenameValidator(schema *otelSchema, lookup metricLookup, anchor semconv, anchorName string) *renameValidator {
	def, known := anchor.metrics[anchorName]
	version := anchor.version
	if !known {
		// The anchor semconv does not declare the queried name, which is an
		// ordinary thing to query: the walk deliberately supports asking for a name
		// the anchor version has already renamed away. Rather than give up on
		// checking anything, take the metric's identity from a version where the
		// name is the current one.
		// version stays the queried one when this fails, so the warning that
		// follows names the semconv the user actually asked for.
		if eraDef, eraVersion, eraKnown := identityFromOwnEra(schema, lookup, anchorName); eraKnown {
			def, version, known = eraDef, eraVersion, true
		}
	}
	return &renameValidator{
		schema:        schema,
		lookup:        lookup,
		anchorName:    anchorName,
		anchorVersion: version,
		anchorDef:     def,
		anchorKnown:   known,
		seen:          map[string]struct{}{},
	}
}

// identityFromOwnEra resolves what name meant at a version where it is the current
// name, for use when the queried semconv version does not declare it.
//
// It declines to answer when the schema retires the name and later reintroduces it
// and the two eras disagree on what the metric is, because then there is no single
// answer to what the queried name denotes and picking one would corroborate hops
// against an identity the user never asked for.
func identityFromOwnEra(schema *otelSchema, lookup metricLookup, name string) (metricDef, string, bool) {
	var (
		found   metricDef
		version string
		ok      bool
	)
	for _, era := range schema.eraVersionsOf(name) {
		def, declared, _ := lookup(era, name)
		if !declared {
			continue
		}
		if ok && !def.sameMetricAs(found) {
			return metricDef{}, "", false
		}
		if !ok {
			found, version, ok = def, era, true
		}
	}
	return found, version, ok
}

func (rv *renameValidator) warn(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if _, dup := rv.seen[msg]; dup {
		return
	}
	rv.seen[msg] = struct{}{}
	rv.warnings = append(rv.warnings, msg)
}

// hopTarget returns the metric name traversing version r's renames from name
// produces, and the version that name is the current one at. ok is false when r
// renames no metric from name, or when the name it produces belongs to a version
// outside the schema's history.
func (rv *renameValidator) hopTarget(r versionRenames, from string) (to, version string, ok bool) {
	older, newer, renamed := r.renameDirection(from)
	if !renamed {
		// An attribute-only hop renames no metric, so there is no metric
		// identity to corroborate.
		return "", "", false
	}
	if from != newer {
		// Walking forward: the hop applies the rename and produces the newer
		// name, which is the current one from this version on.
		return newer, r.version, true
	}
	// Walking back in time: the hop undoes the rename and produces the older
	// name, which was current up to the version before this one.
	predecessor, hasPredecessor := rv.schema.predecessorOf(r.version)
	if !hasPredecessor {
		return "", "", false
	}
	return older, predecessor, true
}

// allowEdge reports whether the walk may traverse version r's renames starting
// from metric name from. A nil validator allows everything, as does an anchor the
// semconv does not declare, since then there is no identity to compare against.
//
// The name this hop produces is compared against the anchor — the metric the
// query asked for — rather than against the other end of the edge. An edge can be
// entirely self-consistent and still be irrelevant: once a name has been renamed
// away it is free for an unrelated metric to reuse later, and the old edge then
// links the reused name to a metric it has nothing to do with. Comparing the two
// endpoints to each other would approve that edge, because in their own era they
// really were the same metric.
//
// It rejects a hop only on positive contradiction — the produced name is
// declared, but as a different unit or instrument than the anchor — because
// fusing metrics measured in different units yields numerically meaningless
// results, which is worse than returning less data. A name a version's semconv
// does not declare is reported and still traversed: it hints at a mis-authored
// edge, but a registry may legitimately ship a semconv trimmed to the metrics its
// operator cares about, and dropping variants over that would lose real series.
func (rv *renameValidator) allowEdge(r versionRenames, from string) bool {
	if rv == nil {
		return true
	}
	to, version, ok := rv.hopTarget(r, from)
	if !ok {
		return true
	}
	if !rv.anchorKnown {
		// No semconv version declares the queried name, or the ones that do
		// disagree on what it is. Every hop is then traversed unchecked, which is
		// reported rather than left silent: this is the case the corroboration
		// exists for, so a caller should know it did not run. Reported only here,
		// where a metric rename is actually being followed, so a query that crosses
		// no rename says nothing.
		rv.warn("metric %q is not declared by semconv %s, and no other version of it settles what the metric is; schema renames of it are being followed without corroboration and may merge unrelated series",
			rv.anchorName, rv.anchorVersion)
		return true
	}

	def, declared, known := rv.lookup(version, to)
	if !known {
		// No semconv shipped for that version, so the hop cannot be checked.
		return true
	}
	if !declared {
		rv.warn("schema version %s links metric %q to %q, but semconv %s does not declare %q as a metric; the rename could not be corroborated",
			r.version, from, to, version, to)
		return true
	}
	if !def.sameMetricAs(rv.anchorDef) {
		rv.warn("queried metric %q is declared as %s/%s by semconv %s, but schema version %s links it to %q, which semconv %s declares as %s/%s; treating them as different metrics and not merging their series",
			rv.anchorName, describeUnit(rv.anchorDef.unit), describeUnit(rv.anchorDef.instrument), rv.anchorVersion,
			r.version, to, version, describeUnit(def.unit), describeUnit(def.instrument))
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

// findVersionAnchorIndex returns the index of the largest version <=
// targetVersion, or -1 when every version renames something newer than
// targetVersion. The versions slice must be sorted in ascending semver order.
//
// Returning -1 rather than clamping to 0 matters, because callers split the slice
// into versions at or before the anchor (versions[:idx+1], walked backward for
// older names) and versions after it (versions[idx+1:], walked forward for newer
// ones). Clamping puts the first renaming version on the backward side even though
// it postdates the anchor, which both walks that rename in the wrong direction and
// leaves it out of the forward chain, truncating everything that follows it.
func findVersionAnchorIndex(versions []versionRenames, targetVersion string) int {
	target := strings.TrimPrefix(targetVersion, "v")
	anchorIdx := -1
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
	variants, applied := walkVersions(schema.versionRenames[:anchorIdx+1], matchers, seen, variants, true, rv)

	// Forward for newer names, from the queried name and from any name the backward
	// walk reached by applying a rename rather than undoing one. A rename edge is
	// stored bidirectionally, so a version at or before the anchor that renames the
	// queried name away is walked backward yet lands on the newer name — as it must,
	// since a user may well query a name the anchor version has already renamed. A
	// later version then renames that name, not the queried one, and seeding the
	// forward walk only with the queried name would cut the chain there.
	//
	// Names the backward walk reached by undoing a rename are deliberately not
	// seeded. Those stopped being current before the anchor, so a later version
	// renaming one of them is not this metric's history but a reuse of a retired
	// name, and following it would pull an unrelated metric into the result.
	for _, start := range append([][]*labels.Matcher{matchers}, applied...) {
		variants, _ = walkVersions(schema.versionRenames[anchorIdx+1:], start, seen, variants, false, rv)
	}

	return variants
}

// walkVersions walks through versions applying renames, chaining results until no new variants.
// If reverse is false, walks oldest→newest; if true, walks newest→oldest.
//
// applied holds the variants produced by a hop that renamed the metric in the
// direction the schema declares it, rather than undoing a rename. Walking backward
// those are the names the metric took at or after the version crossed, which is what
// the forward walk has to continue from; see generateMatcherVariants.
func walkVersions(
	versions []versionRenames,
	matchers []*labels.Matcher,
	seen map[string]struct{},
	result [][]*labels.Matcher,
	reverse bool,
	rv *renameValidator,
) (variants [][]*labels.Matcher, applied [][]*labels.Matcher) {
	// A queue rather than a single chain, because undoing a rename that collapsed
	// several old names onto one yields several names at that hop and each has its
	// own history to follow. Ordinary one-to-one edges never queue anything, so the
	// walk is the same single chain it was for them.
	queue := [][]*labels.Matcher{matchers}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
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
				transformed, alternatives := applyVersionRenames(current, v)
				if transformed == nil {
					continue
				}

				for _, alt := range alternatives {
					altKey := matcherKey(alt)
					if _, exists := seen[altKey]; exists {
						continue
					}
					seen[altKey] = struct{}{}
					result = append(result, alt)
					// Followed from here on its own, since it is a name of this
					// metric like any other. Not added to applied: it comes from
					// undoing a rename, so it predates the anchor.
					queue = append(queue, alt)
				}

				key := matcherKey(transformed)
				if _, exists := seen[key]; exists {
					continue
				}

				seen[key] = struct{}{}
				result = append(result, transformed)
				if transformedName, nameErr := extractMetricName(transformed); nameErr == nil && currentName != "" {
					if newer, ok := v.metricsForward[currentName]; ok && newer == transformedName {
						applied = append(applied, transformed)
					}
				}
				current = transformed
				found = true
				break
			}
			if !found {
				break
			}
		}
	}
	return result, applied
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
//
// alternatives holds the further results of undoing a rename that collapsed several
// old metric names onto one: that edge has one answer per old name, and every one of
// them is a name this metric was known by, so they are all variants to query. It is
// empty for the ordinary one-to-one edge.
func applyVersionRenames(matchers []*labels.Matcher, renames versionRenames) (result []*labels.Matcher, alternatives [][]*labels.Matcher) {
	metricIdx := -1
	for i, m := range matchers {
		var newMatcher *labels.Matcher
		if m.Name == model.MetricNameLabel {
			if variant, ok := renames.metrics[m.Value]; ok {
				newMatcher = labels.MustNewMatcher(m.Type, m.Name, variant)
				if _, forward := renames.metricsForward[m.Value]; !forward {
					// Undoing a rename, so m.Value is the newer name and other old
					// names may have been renamed onto it too.
					metricIdx = i
				}
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
	if result == nil || metricIdx < 0 {
		return result, nil
	}

	// The first old name is already in result (metrics holds it); the rest branch.
	olds := renames.metricsBackward[matchers[metricIdx].Value]
	for _, old := range olds[min(1, len(olds)):] {
		alt := slices.Clone(result)
		alt[metricIdx] = labels.MustNewMatcher(matchers[metricIdx].Type, model.MetricNameLabel, old)
		alternatives = append(alternatives, alt)
	}
	return result, alternatives
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
		// Narrow each version's attribute renames to those that apply to this
		// metric, honouring apply_to_metrics, so a rename declared for one metric
		// does not rewrite the attributes of every other metric. Done on a shallow
		// copy to leave the cached schema untouched.
		scoped := schema
		scoped.versionRenames = scopedVersionRenames(
			schema.versionRenames, metricNameAliases(schema.versionRenames, metricName))

		// Corroborate each rename against the semconv of the versions it
		// connects, so a schema edge that joins two unrelated metrics sharing a
		// surface name is reported rather than silently merged.
		rv := newRenameValidator(&scoped, e.metricLookup(semconvURL), sc, metricName)
		allVariants = generateMatcherVariants(sc.version, &scoped, matchers, rv)
		warnings = append(warnings, rv.warnings...)
		// Map each historical attribute alias back to its anchor-version name so
		// results from older or newer eras merge under the queried version's
		// labels instead of splitting on the renamed attribute. Recomputed per
		// query on purpose: it is a pure function of the cached schema/semconv and
		// costs only a few map ops, far less than the fan-out it feeds.
		attrRenames = buildAttributeRenameMap(sc.version, &scoped, sc.attributesOf(metricName))
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
