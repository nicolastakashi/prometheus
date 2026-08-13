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
	"testing"

	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/tsdb/chunkenc"
)

// TestFanOutResultIsSorted checks that a variant whose labels were rewritten is
// re-sorted before it reaches the merge.
//
// Each variant is queried sorted by the names stored for its own era, and rewriting
// an attribute to its anchor-version name reorders it: here "ttt" sorts after "user"
// but before "tenant". storage.NewMergeSeriesSet assumes every input reports
// strictly increasing labels, so feeding it the rewritten set unsorted let it emit
// series out of order and, where two eras rewrote to the same labels, twice — a
// duplicate labelset PromQL rejects.
//
// The samples are asserted, not just the labels. A merged series computes its labels
// eagerly and its samples only when iterated, so a chain built over a slice the
// merge function still holds looks perfectly well-formed until something reads it.
func TestFanOutResultIsSorted(t *testing.T) {
	// Stored under the 1.0.0 name, so all of these come back in one variant.
	// "user" is rewritten to "tenant" at the 1.1.0 anchor, which moves it before
	// "ttt"; the two "1" series collide on the rewritten labels.
	appendAll := func(t *testing.T, s storage.Storage) {
		t.Helper()
		appendSeries(t, s, "test.counter", 1, 1.0, "ttt", "2")
		appendSeries(t, s, "test.counter", 1, 2.0, "user", "1")
		appendSeries(t, s, "test.counter", 2, 3.0, "tenant", "1")
	}
	// The two colliding series chain into one, so it carries both their samples.
	want := []seriesWithSamples{
		{
			lset:    labels.FromStrings(model.MetricNameLabel, "test", "tenant", "1"),
			samples: []sample{{t: 1, v: 2.0}, {t: 2, v: 3.0}},
		},
		{
			lset:    labels.FromStrings(model.MetricNameLabel, "test", "ttt", "2"),
			samples: []sample{{t: 1, v: 1.0}},
		},
	}

	t.Run("querier", func(t *testing.T) {
		wrapped, _ := newAwareStorage(t)
		appendAll(t, wrapped)

		set := selectAt(t, wrapped, "1.1.0", "test")

		got := collectWithSamples(t, set)
		require.Equal(t, want, got, "expected strictly increasing labels with no duplicates")
	})

	t.Run("chunk querier", func(t *testing.T) {
		wrapped, _ := newAwareStorage(t)
		appendAll(t, wrapped)

		cq, err := wrapped.ChunkQuerier(0, 10)
		require.NoError(t, err)
		t.Cleanup(func() { _ = cq.Close() })

		set := cq.Select(context.Background(), false, nil,
			labels.MustNewMatcher(labels.MatchEqual, model.MetricNameLabel, "test"),
			labels.MustNewMatcher(labels.MatchEqual, "__semconv_url__", "registry/1.1.0"),
			labels.MustNewMatcher(labels.MatchEqual, "__schema_url__", "registry/registry.yaml"),
		)

		got := collectWithSamples(t, storage.NewSeriesSetFromChunkSeriesSet(set))
		require.Equal(t, want, got, "expected strictly increasing labels with no duplicates")
	})
}

type sample struct {
	t int64
	v float64
}

type seriesWithSamples struct {
	lset    labels.Labels
	samples []sample
}

// collectWithSamples drains a series set in order, reading each series' samples.
// Unlike collectSeries it keeps the order and every sample, which is what a set
// fed to a merge has to be checked on: the merge computes a series' labels
// eagerly and its samples lazily, so a malformed chain shows only when read.
func collectWithSamples(t *testing.T, set storage.SeriesSet) []seriesWithSamples {
	t.Helper()
	var out []seriesWithSamples
	for set.Next() {
		s := set.At()
		got := seriesWithSamples{lset: s.Labels()}
		it := s.Iterator(nil)
		for it.Next() == chunkenc.ValFloat {
			ts, v := it.At()
			got.samples = append(got.samples, sample{t: ts, v: v})
			require.LessOrEqual(t, len(got.samples), 16, "runaway iteration on %s", got.lset)
		}
		require.NoError(t, it.Err())
		out = append(out, got)
	}
	require.NoError(t, set.Err())
	return out
}
