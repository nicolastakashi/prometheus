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

package semconv_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/storage/semconv"
	"github.com/prometheus/prometheus/util/teststorage"
)

// renameSchema is a two-version schema renaming old→new at 1.1.0, the shape
// every case below varies the semconv files around.
const renameSchema = `file_format: 1.1.0
schema_url: https://example.com/schemas/1.1.0
versions:
  1.0.0:
  1.1.0:
    metrics:
      changes:
        - rename_metrics:
            %s: %s
`

// metricSemconv renders a semconv file declaring a single metric group. The
// group id follows the "metric.<metric_name>" form that upstream semantic
// conventions lint for, so it necessarily changes whenever the metric name does.
func metricSemconv(metricName, unit, instrument string) []byte {
	return []byte(fmt.Sprintf(`groups:
  - id: metric.%s
    type: metric
    metric_name: %s
    unit: %q
    instrument: %s
    attributes:
      - ref: http.response.status_code
`, metricName, metricName, unit, instrument))
}

// selectRenamed queries metricName anchored at semconv 1.1.0 over the given
// registry and returns the series found plus any warnings raised.
func selectRenamed(t *testing.T, files map[string][]byte, appendUnder, metricName string) (map[string]float64, []string) {
	t.Helper()
	underlying := teststorage.New(t)
	wrapped, err := semconv.AwareStorageWithRegistry(underlying, files)
	require.NoError(t, err)

	appendSeries(t, wrapped, appendUnder, 1, 7.0, "http.response.status_code", "200")

	q, err := wrapped.Querier(0, 10)
	require.NoError(t, err)
	t.Cleanup(func() { _ = q.Close() })

	set := q.Select(context.Background(), false, nil,
		labels.MustNewMatcher(labels.MatchEqual, model.MetricNameLabel, metricName),
		labels.MustNewMatcher(labels.MatchEqual, "__semconv_url__", "registry/1.1.0"),
		labels.MustNewMatcher(labels.MatchEqual, "__schema_url__", "registry/registry.yaml"),
	)
	got := collectSeries(t, set)
	return got, warningStrings(set.Warnings())
}

func TestRenameEdgeValidation(t *testing.T) {
	// A legitimate rename: the metric is the same measurement under a new name,
	// so unit and instrument agree and the historical series must still merge.
	//
	// This is also the case that rules out using the semconv group id as a
	// cross-version identity: the ids here are metric.old.name and
	// metric.new.name, so requiring them to be equal across the edge would
	// reject this rename even though it is exactly the rename the schema exists
	// to describe.
	t.Run("merges a rename whose unit and instrument agree", func(t *testing.T) {
		got, warnings := selectRenamed(t, map[string][]byte{
			"registry.yaml": []byte(fmt.Sprintf(renameSchema, "old.name", "new.name")),
			"1.0.0":         metricSemconv("old.name", "s", "histogram"),
			"1.1.0":         metricSemconv("new.name", "s", "histogram"),
		}, "old.name", "new.name")

		require.Len(t, got, 1, "expected the pre-rename series under the queried name, got %v", got)
		for k := range got {
			require.Contains(t, k, `__name__="new.name"`)
		}
		require.Empty(t, warnings, "a corroborated rename must not warn")
	})

	// The case the schema format cannot express and name traversal cannot
	// detect: two unrelated metrics that happen to share a surface name at
	// different versions. Their units disagree, so merging them would average
	// seconds with a queue depth.
	t.Run("does not merge a rename whose unit disagrees", func(t *testing.T) {
		got, warnings := selectRenamed(t, map[string][]byte{
			"registry.yaml": []byte(fmt.Sprintf(renameSchema, "old.name", "new.name")),
			"1.0.0":         metricSemconv("old.name", "{item}", "updowncounter"),
			"1.1.0":         metricSemconv("new.name", "s", "histogram"),
		}, "old.name", "new.name")

		require.Empty(t, got, "series of a differently-united metric must not be merged in, got %v", got)
		requireWarningsContain(t, warnings, "treating them as different metrics")
		requireWarningsContain(t, warnings, `links it to "old.name"`)
	})

	// Same unit, different instrument: a histogram and a counter are not the
	// same metric even when they measure in the same unit.
	t.Run("does not merge a rename whose instrument disagrees", func(t *testing.T) {
		got, warnings := selectRenamed(t, map[string][]byte{
			"registry.yaml": []byte(fmt.Sprintf(renameSchema, "old.name", "new.name")),
			"1.0.0":         metricSemconv("old.name", "s", "counter"),
			"1.1.0":         metricSemconv("new.name", "s", "histogram"),
		}, "old.name", "new.name")

		require.Empty(t, got, "got %v", got)
		requireWarningsContain(t, warnings, "treating them as different metrics")
	})

	// A registry need not ship a semconv for every version its schema
	// references, so an absent file means "cannot verify" and must leave the
	// existing name-traversal behaviour untouched rather than drop series.
	t.Run("traverses unverifiable renames unchanged when a semconv is absent", func(t *testing.T) {
		got, warnings := selectRenamed(t, map[string][]byte{
			"registry.yaml": []byte(fmt.Sprintf(renameSchema, "old.name", "new.name")),
			"1.1.0":         metricSemconv("new.name", "s", "histogram"),
		}, "old.name", "new.name")

		require.Len(t, got, 1, "expected the pre-rename series to still merge, got %v", got)
		require.Empty(t, warnings, "an unverifiable rename is not evidence of a problem")
	})

	// A name the semconv does not declare as a metric is a strong hint of a
	// mis-authored edge, but a trimmed registry is a legitimate shape, so this
	// is reported without dropping series.
	t.Run("warns but still merges when a name is not declared as a metric", func(t *testing.T) {
		got, warnings := selectRenamed(t, map[string][]byte{
			"registry.yaml": []byte(fmt.Sprintf(renameSchema, "typo.name", "new.name")),
			"1.0.0":         metricSemconv("old.name", "s", "histogram"),
			"1.1.0":         metricSemconv("new.name", "s", "histogram"),
		}, "typo.name", "new.name")

		require.Len(t, got, 1, "expected the series to still merge, got %v", got)
		requireWarningsContain(t, warnings, "could not be corroborated")
	})
}

// TestRecycledMetricName covers the case the schema format cannot express: a
// metric name that was renamed away and later reused by an unrelated metric.
//
//	1.0.0  foo exists, counting bytes
//	2.0.0  schema renames foo to bar
//	5.0.0  a new, unrelated metric claims the name foo, measuring seconds
//
// Querying foo at 5.0.0 means the new metric. The 2.0.0 rename edge concerns the
// old foo and must not drag bar's series in. Note that the edge is entirely
// self-consistent — foo at 1.0.0 and bar at 2.0.0 are both By/counter — so
// comparing an edge's own two endpoints approves it. Only comparing the hop back
// to the queried metric catches this.
func TestRecycledMetricName(t *testing.T) {
	files := map[string][]byte{
		"registry.yaml": []byte(`file_format: 1.1.0
schema_url: https://example.com/schemas/5.0.0
versions:
  1.0.0:
  2.0.0:
    metrics:
      changes:
        - rename_metrics:
            foo: bar
  5.0.0:
`),
		"1.0.0": metricSemconv("foo", "By", "counter"),
		"2.0.0": metricSemconv("bar", "By", "counter"),
		// 5.0.0 declares both the reused name and the metric the old foo became.
		"5.0.0": []byte(`groups:
  - id: metric.foo
    type: metric
    metric_name: foo
    unit: "s"
    instrument: histogram
    attributes:
      - ref: http.response.status_code
  - id: metric.bar
    type: metric
    metric_name: bar
    unit: "By"
    instrument: counter
    attributes:
      - ref: http.response.status_code
`),
	}

	underlying := teststorage.New(t)
	wrapped, err := semconv.AwareStorageWithRegistry(underlying, files)
	require.NoError(t, err)

	// Series of the metric the old foo became. Querying today's foo must not
	// pick these up.
	appendSeries(t, wrapped, "bar", 1, 7.0, "http.response.status_code", "200")

	q, err := wrapped.Querier(0, 10)
	require.NoError(t, err)
	t.Cleanup(func() { _ = q.Close() })

	set := q.Select(context.Background(), false, nil,
		labels.MustNewMatcher(labels.MatchEqual, model.MetricNameLabel, "foo"),
		labels.MustNewMatcher(labels.MatchEqual, "__semconv_url__", "registry/5.0.0"),
		labels.MustNewMatcher(labels.MatchEqual, "__schema_url__", "registry/registry.yaml"),
	)
	got := collectSeries(t, set)
	require.Empty(t, got, "an unrelated metric that once held this name must not be merged in, got %v", got)
	requireWarningsContain(t, warningStrings(set.Warnings()), "treating them as different metrics")
}

// TestAttributeRenameScope checks that an attribute rename restricted by
// apply_to_metrics does not rewrite the attributes of other metrics. The schema
// scopes user→tenant to scoped.metric only, so a series of other.metric that
// carries user must keep it.
func TestAttributeRenameScope(t *testing.T) {
	schema := []byte(`file_format: 1.1.0
schema_url: https://example.com/schemas/1.1.0
versions:
  1.0.0:
  1.1.0:
    metrics:
      changes:
        - rename_attributes:
            attribute_map:
              user: tenant
            apply_to_metrics:
              - scoped.metric
`)
	semconv110 := []byte(`groups:
  - id: metric.scoped.metric
    type: metric
    metric_name: scoped.metric
    unit: "s"
    instrument: histogram
    attributes:
      - ref: tenant
  - id: metric.other.metric
    type: metric
    metric_name: other.metric
    unit: "s"
    instrument: histogram
    attributes:
      - ref: tenant
`)

	underlying := teststorage.New(t)
	wrapped, err := semconv.AwareStorageWithRegistry(underlying, map[string][]byte{
		"registry.yaml": schema,
		"1.1.0":         semconv110,
	})
	require.NoError(t, err)

	appendSeries(t, wrapped, "scoped.metric", 1, 1.0, "user", "alice")
	appendSeries(t, wrapped, "other.metric", 1, 2.0, "user", "bob")

	q, err := wrapped.Querier(0, 10)
	require.NoError(t, err)
	t.Cleanup(func() { _ = q.Close() })

	selectMetric := func(name string) map[string]float64 {
		return collectSeries(t, q.Select(context.Background(), false, nil,
			labels.MustNewMatcher(labels.MatchEqual, model.MetricNameLabel, name),
			labels.MustNewMatcher(labels.MatchEqual, "__semconv_url__", "registry/1.1.0"),
			labels.MustNewMatcher(labels.MatchEqual, "__schema_url__", "registry/registry.yaml"),
		))
	}

	// The metric the rename is scoped to still has its historical attribute
	// normalised to the anchor version's name.
	got := selectMetric("scoped.metric")
	require.Len(t, got, 1, "got %v", got)
	for k := range got {
		require.Contains(t, k, `tenant="alice"`, "the scoped metric must be normalised")
	}

	// Any other metric must be left alone. Before apply_to_metrics was honoured,
	// this attribute was rewritten to tenant as well.
	got = selectMetric("other.metric")
	require.Len(t, got, 1, "got %v", got)
	for k := range got {
		require.Contains(t, k, `user="bob"`, "a rename scoped to another metric must not apply here")
		require.NotContains(t, k, "tenant=")
	}
}

func TestAmbiguousMetricNameWarns(t *testing.T) {
	// Two groups declaring the same metric_name: the collision that previously
	// resolved to whichever group was parsed last, with no warning.
	ambiguous := []byte(`groups:
  - id: metric.shared.name
    type: metric
    metric_name: shared.name
    unit: "s"
    instrument: histogram
    attributes:
      - ref: http.response.status_code
  - id: metric.shared.name.other
    type: metric
    metric_name: shared.name
    unit: "{item}"
    instrument: updowncounter
    attributes:
      - ref: queue.name
`)

	underlying := teststorage.New(t)
	wrapped, err := semconv.AwareStorageWithRegistry(underlying, map[string][]byte{
		"registry.yaml": []byte(fmt.Sprintf(renameSchema, "old.name", "other.name")),
		"1.1.0":         ambiguous,
	})
	require.NoError(t, err)

	appendSeries(t, wrapped, "shared.name", 1, 7.0)

	q, err := wrapped.Querier(0, 10)
	require.NoError(t, err)
	t.Cleanup(func() { _ = q.Close() })

	matchers := []*labels.Matcher{
		labels.MustNewMatcher(labels.MatchEqual, model.MetricNameLabel, "shared.name"),
		labels.MustNewMatcher(labels.MatchEqual, "__semconv_url__", "registry/1.1.0"),
		labels.MustNewMatcher(labels.MatchEqual, "__schema_url__", "registry/registry.yaml"),
	}

	t.Run("Select", func(t *testing.T) {
		set := q.Select(context.Background(), false, nil, matchers...)
		require.NotEmpty(t, collectSeries(t, set))
		requireWarningsContain(t, warningStrings(set.Warnings()), "declared by more than one group")
	})

	t.Run("LabelNames", func(t *testing.T) {
		_, anns, err := q.LabelNames(context.Background(), nil, matchers...)
		require.NoError(t, err)
		requireWarningsContain(t, warningStrings(anns), "declared by more than one group")
	})

	t.Run("LabelValues", func(t *testing.T) {
		_, anns, err := q.LabelValues(context.Background(), "http.response.status_code", nil, matchers...)
		require.NoError(t, err)
		requireWarningsContain(t, warningStrings(anns), "declared by more than one group")
	})
}

// TestChunkQuerierSurfacesWarnings checks the ChunkQuerier path annotates too,
// since it fans out through the same resolver as Querier.
func TestChunkQuerierSurfacesWarnings(t *testing.T) {
	underlying := teststorage.New(t)
	wrapped, err := semconv.AwareStorageWithRegistry(underlying, map[string][]byte{
		"registry.yaml": []byte(fmt.Sprintf(renameSchema, "old.name", "new.name")),
		"1.0.0":         metricSemconv("old.name", "{item}", "updowncounter"),
		"1.1.0":         metricSemconv("new.name", "s", "histogram"),
	})
	require.NoError(t, err)
	appendSeries(t, wrapped, "new.name", 1, 7.0)

	cq, err := wrapped.ChunkQuerier(0, 10)
	require.NoError(t, err)
	t.Cleanup(func() { _ = cq.Close() })

	set := cq.Select(context.Background(), false, nil,
		labels.MustNewMatcher(labels.MatchEqual, model.MetricNameLabel, "new.name"),
		labels.MustNewMatcher(labels.MatchEqual, "__semconv_url__", "registry/1.1.0"),
		labels.MustNewMatcher(labels.MatchEqual, "__schema_url__", "registry/registry.yaml"),
	)
	var n int
	for set.Next() {
		n++
	}
	require.NoError(t, set.Err())
	require.Equal(t, 1, n, "the queried metric's own series must still be returned")

	var found bool
	for _, w := range warningStrings(set.Warnings()) {
		if strings.Contains(w, "treating them as different metrics") {
			found = true
		}
	}
	require.True(t, found, "expected the chunk querier to surface the mis-linked rename warning")
}
