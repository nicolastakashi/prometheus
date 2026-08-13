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
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/prometheus/common/model"
	"golang.org/x/sync/errgroup"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/util/annotations"
)

const (
	semconvURLLabel = "__semconv_url__"
	schemaURLLabel  = "__schema_url__"

	// fanOutLimit caps the number of concurrent queries issued to the
	// underlying storage when a Select / LabelNames / LabelValues call fans
	// out across semconv variants. The schema-version fan-out can produce
	// several variants per call; without a cap, concurrent PromQL evaluation
	// would spawn unbounded goroutines. The chosen value follows the same
	// errgroup.SetLimit convention used elsewhere in the codebase (see
	// discovery/aws/rds.go).
	fanOutLimit = 16
)

// ErrSchemaWarning is the sentinel chained into every warning emitted by the
// semconv-aware querier. It wraps annotations.PromQLWarning so warnings are
// surfaced as PromQL warnings by util/annotations.AsStrings, and so callers
// can recognise the warning class via errors.Is(err, ErrSchemaWarning).
var ErrSchemaWarning = fmt.Errorf("%w: semconv", annotations.PromQLWarning)

// schemaWarning wraps msg in the ErrSchemaWarning sentinel so the resulting error
// is classified as a PromQL warning when surfaced through Annotations.
func schemaWarning(msg string) error {
	return fmt.Errorf("%w %s", ErrSchemaWarning, msg)
}

// AwareStorage wraps the given storage so that PromQL queries carrying a
// __semconv_url__ or __schema_url__ matcher are answered by fanning out
// across the historical metric and attribute names declared by the referenced
// semconv/OTel schema. Results are merged so callers observe a single
// canonical naming. Queries without those matchers are passed through
// unchanged.
func AwareStorage(s storage.Storage) storage.Storage {
	return &awareStorage{Storage: s, engine: newSchemaEngine(embeddedRegistry)}
}

// AwareStorageWithRegistry behaves like AwareStorage but resolves __semconv_url__
// and __schema_url__ matchers against an operator-provided registry instead of
// the embedded one, which it fully replaces. files holds the registry-root files
// keyed by base name (e.g. "registry.yaml", "1.0.0"). It returns an error if
// files is not a valid registry (empty, or a file fails to parse as the semconv
// or OTel schema its name implies), so callers can fail fast at startup.
func AwareStorageWithRegistry(s storage.Storage, files map[string][]byte) (storage.Storage, error) {
	if err := validateRegistryFiles(files); err != nil {
		return nil, err
	}
	return &awareStorage{Storage: s, engine: newSchemaEngine(newRegistrySource(files))}, nil
}

type awareStorage struct {
	storage.Storage

	engine *schemaEngine
}

func (s *awareStorage) Querier(mint, maxt int64) (storage.Querier, error) {
	q, err := s.Storage.Querier(mint, maxt)
	if err != nil {
		return nil, err
	}
	return &awareQuerier{Querier: q, engine: s.engine}, nil
}

func (s *awareStorage) ChunkQuerier(mint, maxt int64) (storage.ChunkQuerier, error) {
	q, err := s.Storage.ChunkQuerier(mint, maxt)
	if err != nil {
		return nil, err
	}
	return &awareChunkQuerier{ChunkQuerier: q, engine: s.engine}, nil
}

// classifyMatchers inspects matchers for the reserved __semconv_url__ and
// __schema_url__ labels and decides how the query is handled. A non-empty
// warning means pass through and annotate the result. fanout=true means the
// caller should fan out via findMatcherVariants; fanout=false with an empty
// warning means a plain passthrough (no schematization was requested).
//
// __schema_url__ triggers schema-version rename fan-out and requires
// __semconv_url__ (the registry source); __semconv_url__ on its own has no
// effect and is reported as such, rather than silently doing nothing.
func classifyMatchers(matchers []*labels.Matcher) (semconvURL, schemaURL, warning string, fanout bool) {
	dup := func(label string) string {
		return fmt.Sprintf("%s matcher was used more than once, schematization logic is skipped for %v", label, matchers)
	}
	ambiguous := func(label string) string {
		return fmt.Sprintf("%s matcher is ambiguous (not equal type), schematization logic is skipped for %v", label, matchers)
	}
	for _, m := range matchers {
		switch m.Name {
		case semconvURLLabel:
			if semconvURL != "" {
				return "", "", dup(semconvURLLabel), false
			}
			if m.Type != labels.MatchEqual {
				return "", "", ambiguous(semconvURLLabel), false
			}
			semconvURL = m.Value
		case schemaURLLabel:
			if schemaURL != "" {
				return "", "", dup(schemaURLLabel), false
			}
			if m.Type != labels.MatchEqual {
				return "", "", ambiguous(schemaURLLabel), false
			}
			schemaURL = m.Value
		}
	}

	if semconvURL == "" {
		if schemaURL != "" {
			return "", "", fmt.Sprintf("__schema_url__ requires __semconv_url__, schematization logic is skipped for %v", matchers), false
		}
		return "", "", "", false // Nothing requested.
	}

	if schemaURL == "" {
		return "", "", fmt.Sprintf("__semconv_url__ alone has no effect; add __schema_url__ to fan out, schematization logic is skipped for %v", matchers), false
	}

	return semconvURL, schemaURL, "", true
}

// variantErrorWarning formats the passthrough warning for a findMatcherVariants failure.
func variantErrorWarning(matchers []*labels.Matcher, err error) string {
	return fmt.Sprintf("failed to find variants, schematization logic is skipped for %v: %v", matchers, err)
}

// isReservedLabel reports whether name is one of the wrapper's reserved matcher
// labels.
func isReservedLabel(name string) bool {
	return name == semconvURLLabel || name == schemaURLLabel
}

// stripReservedLabels returns matchers without the wrapper's reserved labels so
// a passthrough query behaves as if the wrapper were absent (rather than
// matching the never-present reserved labels and returning nothing). It returns
// the input unchanged when no reserved label is present, so the common path
// allocates nothing.
func stripReservedLabels(matchers []*labels.Matcher) []*labels.Matcher {
	hasReserved := false
	for _, m := range matchers {
		if isReservedLabel(m.Name) {
			hasReserved = true
			break
		}
	}
	if !hasReserved {
		return matchers
	}
	out := make([]*labels.Matcher, 0, len(matchers))
	for _, m := range matchers {
		if !isReservedLabel(m.Name) {
			out = append(out, m)
		}
	}
	return out
}

// reverseLabelName returns the canonical label name for n, looked up in the
// query's labelMapping. If no mapping applies n is returned unchanged.
// Note: the metric name (model.MetricNameLabel) is not reverse-mapped here —
// it is correctly reported as a label name by underlying storage. Value-level
// canonicalisation for __name__ is handled in queryLabelValues.
func reverseLabelName(q queryContext, n string) string {
	if q.labelMapping == nil {
		return n
	}
	if canon, ok := q.labelMapping.translatedLabels[n]; ok {
		return canon
	}
	return n
}

type awareQuerier struct {
	storage.Querier

	engine *schemaEngine
}

func (q *awareQuerier) Select(ctx context.Context, sortSeries bool, hints *storage.SelectHints, matchers ...*labels.Matcher) storage.SeriesSet {
	semconvURL, schemaURL, warning, fanout := classifyMatchers(matchers)
	passthrough := stripReservedLabels(matchers)
	if warning != "" {
		return annotateSeriesSet(q.Querier.Select(ctx, sortSeries, hints, passthrough...), warning)
	}
	if !fanout {
		return q.Querier.Select(ctx, sortSeries, hints, passthrough...)
	}

	variants, qCtx, err := q.engine.findMatcherVariants(semconvURL, schemaURL, matchers)
	if err != nil {
		return annotateSeriesSet(
			q.Querier.Select(ctx, sortSeries, hints, passthrough...),
			variantErrorWarning(matchers, err),
		)
	}
	if qCtx.labelMapping == nil {
		// No transformation needed: passthrough.
		return q.Querier.Select(ctx, sortSeries, hints, passthrough...)
	}

	seriesSets := make([]storage.SeriesSet, len(variants))
	// Deliberately not errgroup.WithContext: a Select is lazy, so its context must
	// outlive g.Wait() here, and WithContext cancels its derived context as soon as
	// Wait returns. The variants are read only after that, which with a streaming
	// underlying querier would abort the read mid-stream. Nothing here returns an
	// error, so cancellation propagation buys nothing anyway.
	var g errgroup.Group
	g.SetLimit(fanOutLimit)
	resort := needsResort(qCtx)
	for i, ms := range variants {
		g.Go(func() error {
			set := storage.SeriesSet(&awareSeriesSet{
				SeriesSet: q.Querier.Select(ctx, true, hints, ms...),
				engine:    q.engine,
				qCtx:      qCtx,
			})
			if resort {
				// Left lazy on purpose, which means the drains happen one after
				// another: NewMergeSeriesSet pre-advances every input when it is
				// constructed, and advancing a buffering set drains it, so all of
				// them drain on the caller's goroutine.
				//
				// Draining here instead, inside the group, would parallelise that
				// but is not allowed. Only storage.Storage is goroutine-safe; a
				// Querier is not, and tsdb's demonstrably is not — iterating a
				// series set calls headIndexReader.Series, which writes to a scratch
				// buffer shared by every set derived from the same querier. Two
				// variants drained at once corrupt it. Selecting concurrently is
				// fine, since the sets are only built there and not read.
				//
				// Parallelising the drain means one Querier per variant, which is a
				// change to what a fan-out holds open, not just to where load runs.
				set = newSortedSeriesSet(set)
			}
			seriesSets[i] = set
			return nil
		})
	}
	_ = g.Wait()
	merged := storage.NewMergeSeriesSet(seriesSets, 0, storage.ChainedSeriesMerge)
	if len(qCtx.warnings) > 0 {
		return annotateSeriesSet(merged, qCtx.warnings...)
	}
	return merged
}

func (q *awareQuerier) LabelNames(ctx context.Context, hints *storage.LabelHints, matchers ...*labels.Matcher) ([]string, annotations.Annotations, error) {
	return queryLabelNames(ctx, q.Querier, q.engine, hints, matchers)
}

func (q *awareQuerier) LabelValues(ctx context.Context, name string, hints *storage.LabelHints, matchers ...*labels.Matcher) ([]string, annotations.Annotations, error) {
	return queryLabelValues(ctx, q.Querier, q.engine, name, hints, matchers)
}

type awareChunkQuerier struct {
	storage.ChunkQuerier

	engine *schemaEngine
}

func (q *awareChunkQuerier) Select(ctx context.Context, sortSeries bool, hints *storage.SelectHints, matchers ...*labels.Matcher) storage.ChunkSeriesSet {
	semconvURL, schemaURL, warning, fanout := classifyMatchers(matchers)
	passthrough := stripReservedLabels(matchers)
	if warning != "" {
		return annotateChunkSeriesSet(q.ChunkQuerier.Select(ctx, sortSeries, hints, passthrough...), warning)
	}
	if !fanout {
		return q.ChunkQuerier.Select(ctx, sortSeries, hints, passthrough...)
	}

	variants, qCtx, err := q.engine.findMatcherVariants(semconvURL, schemaURL, matchers)
	if err != nil {
		return annotateChunkSeriesSet(
			q.ChunkQuerier.Select(ctx, sortSeries, hints, passthrough...),
			variantErrorWarning(matchers, err),
		)
	}
	if qCtx.labelMapping == nil {
		return q.ChunkQuerier.Select(ctx, sortSeries, hints, passthrough...)
	}

	chunkSeriesSets := make([]storage.ChunkSeriesSet, len(variants))
	// ctx rather than an errgroup-derived context, and re-sorted only where a
	// rewrite can reorder a set, draining inside the group; see the Select above.
	var g errgroup.Group
	g.SetLimit(fanOutLimit)
	resort := needsResort(qCtx)
	for i, ms := range variants {
		g.Go(func() error {
			set := storage.ChunkSeriesSet(&awareChunkSeriesSet{
				ChunkSeriesSet: q.ChunkQuerier.Select(ctx, true, hints, ms...),
				engine:         q.engine,
				qCtx:           qCtx,
			})
			if resort {
				// Lazy, so the drains do not overlap; see the Select above.
				set = newSortedChunkSeriesSet(set)
			}
			chunkSeriesSets[i] = set
			return nil
		})
	}
	_ = g.Wait()
	merged := storage.NewMergeChunkSeriesSet(chunkSeriesSets, 0, storage.NewCompactingChunkSeriesMerger(storage.ChainedSeriesMerge))
	if len(qCtx.warnings) > 0 {
		return annotateChunkSeriesSet(merged, qCtx.warnings...)
	}
	return merged
}

func (q *awareChunkQuerier) LabelNames(ctx context.Context, hints *storage.LabelHints, matchers ...*labels.Matcher) ([]string, annotations.Annotations, error) {
	return queryLabelNames(ctx, q.ChunkQuerier, q.engine, hints, matchers)
}

func (q *awareChunkQuerier) LabelValues(ctx context.Context, name string, hints *storage.LabelHints, matchers ...*labels.Matcher) ([]string, annotations.Annotations, error) {
	return queryLabelValues(ctx, q.ChunkQuerier, q.engine, name, hints, matchers)
}

// labelQuerier captures the label-query surface that both storage.Querier and
// storage.ChunkQuerier expose through the embedded storage.LabelQuerier.
type labelQuerier interface {
	LabelValues(ctx context.Context, name string, hints *storage.LabelHints, matchers ...*labels.Matcher) ([]string, annotations.Annotations, error)
	LabelNames(ctx context.Context, hints *storage.LabelHints, matchers ...*labels.Matcher) ([]string, annotations.Annotations, error)
}

func queryLabelNames(ctx context.Context, q labelQuerier, e *schemaEngine, hints *storage.LabelHints, matchers []*labels.Matcher) ([]string, annotations.Annotations, error) {
	semconvURL, schemaURL, warning, fanout := classifyMatchers(matchers)
	passthrough := stripReservedLabels(matchers)
	if warning != "" {
		names, anns, err := q.LabelNames(ctx, hints, passthrough...)
		return names, anns.Add(schemaWarning(warning)), err
	}
	if !fanout {
		return q.LabelNames(ctx, hints, passthrough...)
	}

	variants, qCtx, err := e.findMatcherVariants(semconvURL, schemaURL, matchers)
	if err != nil {
		names, anns, lerr := q.LabelNames(ctx, hints, passthrough...)
		return names, anns.Add(schemaWarning(variantErrorWarning(matchers, err))), lerr
	}
	if qCtx.labelMapping == nil {
		return q.LabelNames(ctx, hints, passthrough...)
	}

	type partial struct {
		names []string
		anns  annotations.Annotations
		err   error
	}
	results := make([]partial, len(variants))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(fanOutLimit)
	for i, ms := range variants {
		g.Go(func() error {
			n, a, err := q.LabelNames(gctx, hints, ms...)
			results[i] = partial{names: n, anns: a, err: err}
			return nil
		})
	}
	_ = g.Wait()

	seen := make(map[string]struct{})
	var combined []string
	var combinedAnns annotations.Annotations
	var errs []error
	for _, p := range results {
		if p.err != nil {
			errs = append(errs, p.err)
		}
		combinedAnns.Merge(p.anns)
		for _, n := range p.names {
			if isReservedLabel(n) {
				// Select strips these from the series it returns, so reporting
				// them as label names would advertise labels no series carries.
				continue
			}
			canonical := reverseLabelName(qCtx, n)
			if _, ok := seen[canonical]; ok {
				continue
			}
			seen[canonical] = struct{}{}
			combined = append(combined, canonical)
		}
	}
	slices.Sort(combined)
	return combined, addWarnings(combinedAnns, qCtx), errors.Join(errs...)
}

func queryLabelValues(ctx context.Context, q labelQuerier, e *schemaEngine, name string, hints *storage.LabelHints, matchers []*labels.Matcher) ([]string, annotations.Annotations, error) {
	semconvURL, schemaURL, warning, fanout := classifyMatchers(matchers)
	passthrough := stripReservedLabels(matchers)
	if warning != "" {
		values, anns, err := q.LabelValues(ctx, name, hints, passthrough...)
		return values, anns.Add(schemaWarning(warning)), err
	}
	if !fanout {
		return q.LabelValues(ctx, name, hints, passthrough...)
	}

	variants, qCtx, err := e.findMatcherVariants(semconvURL, schemaURL, matchers)
	if err != nil {
		values, anns, lerr := q.LabelValues(ctx, name, hints, passthrough...)
		return values, anns.Add(schemaWarning(variantErrorWarning(matchers, err))), lerr
	}
	if qCtx.labelMapping == nil {
		return q.LabelValues(ctx, name, hints, passthrough...)
	}

	// Each variant stores the queried attribute under its own era's name, so we
	// query every historical alias of `name` across every variant and merge the
	// values; mismatched (variant, alias) pairs simply return nothing. For
	// __name__ there are no attribute aliases (aliasesOf returns just the name),
	// and its values are collapsed to the canonical metric below.
	//
	// name is canonicalised first, so asking for a historical name of a renamed
	// attribute fans out over the same alias set as asking for its anchor-version
	// name; otherwise aliasesOf, which only expands a canonical name, would return
	// the historical name alone and miss every other era.
	aliases := qCtx.labelMapping.aliasesOf(reverseLabelName(qCtx, name))

	type partial struct {
		values []string
		anns   annotations.Annotations
		err    error
	}
	results := make([]partial, len(variants)*len(aliases))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(fanOutLimit)
	for vi, ms := range variants {
		for ai, alias := range aliases {
			idx := vi*len(aliases) + ai
			g.Go(func() error {
				v, a, err := q.LabelValues(gctx, alias, hints, ms...)
				results[idx] = partial{values: v, anns: a, err: err}
				return nil
			})
		}
	}
	_ = g.Wait()

	// When the caller asked for values of __name__, every variant's results
	// are different escapings of the same canonical metric; collapse them.
	// qCtx.labelMapping is non-nil here (early return above) and
	// buildLabelMapping unconditionally sets translatedMetric, so the
	// canonical name is always available when name == __name__.
	metricNameQuery := name == model.MetricNameLabel

	seen := make(map[string]struct{})
	var combined []string
	var combinedAnns annotations.Annotations
	var errs []error
	for _, p := range results {
		if p.err != nil {
			errs = append(errs, p.err)
		}
		combinedAnns.Merge(p.anns)
		for _, v := range p.values {
			if metricNameQuery {
				v = qCtx.labelMapping.translatedMetric
			}
			if _, ok := seen[v]; ok {
				continue
			}
			seen[v] = struct{}{}
			combined = append(combined, v)
		}
	}
	slices.Sort(combined)
	return combined, addWarnings(combinedAnns, qCtx), errors.Join(errs...)
}

type annotatedSeriesSet struct {
	storage.SeriesSet

	warnings []string
}

func annotateSeriesSet(s storage.SeriesSet, warnings ...string) storage.SeriesSet {
	return &annotatedSeriesSet{warnings: warnings, SeriesSet: s}
}

func (s *annotatedSeriesSet) Warnings() annotations.Annotations {
	got := s.SeriesSet.Warnings()
	for _, w := range s.warnings {
		got = got.Add(schemaWarning(w))
	}
	return got
}

// addWarnings merges the query-resolution warnings collected in qCtx into anns.
func addWarnings(anns annotations.Annotations, qCtx queryContext) annotations.Annotations {
	for _, w := range qCtx.warnings {
		anns = anns.Add(schemaWarning(w))
	}
	return anns
}

type annotatedChunkSeriesSet struct {
	storage.ChunkSeriesSet

	warnings []string
}

func annotateChunkSeriesSet(s storage.ChunkSeriesSet, warnings ...string) storage.ChunkSeriesSet {
	return &annotatedChunkSeriesSet{warnings: warnings, ChunkSeriesSet: s}
}

func (s *annotatedChunkSeriesSet) Warnings() annotations.Annotations {
	got := s.ChunkSeriesSet.Warnings()
	for _, w := range s.warnings {
		got = got.Add(schemaWarning(w))
	}
	return got
}

// needsResort reports whether rewriting a variant's labels can change the order
// the underlying querier returned them in, which is what decides whether a variant
// has to be buffered and sorted before the merge sees it.
//
// Only an attribute rename can. Every series in a variant matches the same equality
// matcher on __name__, so rewriting the metric name replaces the same value in all
// of them and leaves their relative order alone; renaming an attribute moves that
// label within a series and so moves the series within the set. Two series can also
// collide on the rewritten labels, but only by differing in a renamed attribute's
// name, so the same condition covers it.
//
// This takes it that no stored series carries the reserved __semconv_url__ /
// __schema_url__ labels, which transformSeries strips and whose removal could
// likewise reorder a set. They are query-time matchers that nothing writes, and
// __-prefixed labels are dropped from scraped samples.
func needsResort(qCtx queryContext) bool {
	return qCtx.labelMapping != nil && len(qCtx.labelMapping.translatedLabels) > 0
}

// sortAndChain returns in sorted by labels, with each run of series carrying
// identical labels collapsed into one via merge.
//
// Both are needed because rewriting labels can reorder a set and can make two
// series collide. A variant queries one naming era and its series come back sorted
// by that era's names; rewriting an attribute to its anchor-version name moves it
// in the ordering, and two series distinguished only by the era of an attribute
// name rewrite to the very same labels. storage.NewMergeSeriesSet assumes each
// input reports strictly increasing labels, so it would emit the reordered series
// out of order and the collided ones twice.
func sortAndChain[T interface{ Labels() labels.Labels }](in []T, merge func(...T) T) []T {
	slices.SortStableFunc(in, func(a, b T) int {
		return labels.Compare(a.Labels(), b.Labels())
	})
	// A fresh slice, deliberately not in[:0]: the merge functions retain the slice
	// they are handed and read it only when the merged series is iterated, so
	// compacting in place would write a merged series back into the very range its
	// own chain still points at, and iterating it would recurse forever.
	out := make([]T, 0, len(in))
	for i := 0; i < len(in); {
		j := i + 1
		for j < len(in) && labels.Equal(in[j].Labels(), in[i].Labels()) {
			j++
		}
		if j-i == 1 {
			out = append(out, in[i])
		} else {
			out = append(out, merge(in[i:j]...))
		}
		i = j
	}
	return out
}

// sortedSeriesSet re-sorts a series set whose labels have been rewritten, so it
// can be fed to storage.NewMergeSeriesSet.
//
// It buffers the whole set on first use, which the SeriesSet contract permits:
// "Returned series should be iterable even after Next is called", so only the
// series handles are held, not their samples. That is the price of rewriting labels
// before merging rather than after — the sort order is not known until every label
// has been rewritten.
type sortedSeriesSet struct {
	storage.SeriesSet

	series []storage.Series
	idx    int
	loaded bool
}

func newSortedSeriesSet(s storage.SeriesSet) *sortedSeriesSet {
	return &sortedSeriesSet{SeriesSet: s, idx: -1}
}

// load drains and sorts the underlying set, on the first Next. It must stay on the
// reading goroutine: the underlying querier is not safe to iterate concurrently.
func (s *sortedSeriesSet) load() {
	if s.loaded {
		return
	}
	s.loaded = true
	for s.SeriesSet.Next() {
		s.series = append(s.series, s.SeriesSet.At())
	}
	s.series = sortAndChain(s.series, storage.ChainedSeriesMerge)
}

func (s *sortedSeriesSet) Next() bool {
	s.load()
	if s.Err() != nil {
		return false
	}
	s.idx++
	return s.idx < len(s.series)
}

func (s *sortedSeriesSet) At() storage.Series {
	return s.series[s.idx]
}

// sortedChunkSeriesSet is sortedSeriesSet for chunk series; see there.
type sortedChunkSeriesSet struct {
	storage.ChunkSeriesSet

	series []storage.ChunkSeries
	idx    int
	loaded bool
}

func newSortedChunkSeriesSet(s storage.ChunkSeriesSet) *sortedChunkSeriesSet {
	return &sortedChunkSeriesSet{ChunkSeriesSet: s, idx: -1}
}

// load drains and sorts the underlying set on the first Next; see
// sortedSeriesSet.load.
func (s *sortedChunkSeriesSet) load() {
	if s.loaded {
		return
	}
	s.loaded = true
	for s.ChunkSeriesSet.Next() {
		s.series = append(s.series, s.ChunkSeriesSet.At())
	}
	s.series = sortAndChain(s.series, storage.NewCompactingChunkSeriesMerger(storage.ChainedSeriesMerge))
}

func (s *sortedChunkSeriesSet) Next() bool {
	s.load()
	if s.Err() != nil {
		return false
	}
	s.idx++
	return s.idx < len(s.series)
}

func (s *sortedChunkSeriesSet) At() storage.ChunkSeries {
	return s.series[s.idx]
}

type awareSeriesSet struct {
	storage.SeriesSet

	qCtx   queryContext
	engine *schemaEngine

	at storage.Series
}

func (s *awareSeriesSet) At() storage.Series {
	return s.at
}

func (s *awareSeriesSet) Next() bool {
	if s.Err() != nil {
		return false
	}
	if !s.SeriesSet.Next() {
		return false
	}
	at := s.SeriesSet.At()
	s.at = &awareSeries{Series: at, lbls: s.engine.transformSeries(s.qCtx, at.Labels())}
	return true
}

type awareSeries struct {
	storage.Series

	lbls labels.Labels
}

func (s *awareSeries) Labels() labels.Labels {
	return s.lbls
}

type awareChunkSeriesSet struct {
	storage.ChunkSeriesSet

	qCtx   queryContext
	engine *schemaEngine

	at storage.ChunkSeries
}

func (s *awareChunkSeriesSet) At() storage.ChunkSeries {
	return s.at
}

func (s *awareChunkSeriesSet) Next() bool {
	if s.Err() != nil {
		return false
	}
	if !s.ChunkSeriesSet.Next() {
		return false
	}
	at := s.ChunkSeriesSet.At()
	s.at = &awareChunkSeries{ChunkSeries: at, lbls: s.engine.transformSeries(s.qCtx, at.Labels())}
	return true
}

type awareChunkSeries struct {
	storage.ChunkSeries

	lbls labels.Labels
}

func (s *awareChunkSeries) Labels() labels.Labels {
	return s.lbls
}
