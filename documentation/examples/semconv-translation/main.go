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

// This demo showcases versioned OTel semantic-conventions read in Prometheus.
// It simulates a native-OTel producer whose metric and one of its attributes
// are renamed across semantic-conventions versions. By default semconv 1.0.0
// names the metric "test.counter" with attribute "user" and semconv 1.1.0
// renames them to "test" and "tenant"; the --old-metric, --new-metric,
// --old-attr, --new-attr, --old-version, --new-version and --schema flags
// point the demo at a different registry and rename.
//
// The demo shows:
//   - How a rename breaks queries (each name covers only its own era)
//   - How __schema_url__ walks the schema's version renames so a single query
//     surfaces both eras under the requested version's metric and attribute names
//
// Run with: go run ./documentation/examples/semconv-translation
//
// For browser demo with Prometheus UI:
//
//	go run ./documentation/examples/semconv-translation --data-dir=/tmp/demo-data --populate-only
//	./prometheus --storage.tsdb.path=/tmp/demo-data --config.file=/dev/null --enable-feature=semconv-versioned-read
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/common/promslog"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/storage/semconv"
	"github.com/prometheus/prometheus/tsdb"
)

// ANSI color codes for terminal output.
const (
	colorReset   = "\033[0m"
	colorBold    = "\033[1m"
	colorCyan    = "\033[36m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorMagenta = "\033[35m"
)

var (
	dataDir      = flag.String("data-dir", "", "TSDB data directory (default: temp directory, deleted on exit)")
	populateOnly = flag.Bool("populate-only", false, "Only populate data, skip query phase (for use with demo.sh)")

	oldMetric = flag.String("old-metric", "test.counter", "Metric name in the earlier semconv version")
	newMetric = flag.String("new-metric", "test", "Metric name in the later semconv version")
	oldAttr   = flag.String("old-attr", "user", "Attribute name in the earlier semconv version")
	newAttr   = flag.String("new-attr", "tenant", "Attribute name in the later semconv version")
	oldVer    = flag.String("old-version", "1.0.0", "Earlier semconv version")
	newVer    = flag.String("new-version", "1.1.0", "Later semconv version")
	schema    = flag.String("schema", "registry/registry.yaml", "Embedded schema file to resolve renames against")
)

// legacyNameRE matches the classic Prometheus name grammar. PromQL accepts
// those bare; every other name - a native OTel one with dots, say - has to be
// quoted, so the flags must not be interpolated into a query unchecked.
var legacyNameRE = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_:]*$`)
var legacyLabelNameRE = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// lbl renders a label name for a matcher or a grouping clause.
func lbl(name string) string {
	if legacyLabelNameRE.MatchString(name) {
		return name
	}
	return strconv.Quote(name)
}

// sel renders a bare metric name as a PromQL selector.
func sel(metric string) string {
	if legacyNameRE.MatchString(metric) {
		return metric
	}
	return fmt.Sprintf("{%s}", strconv.Quote(metric))
}

// selWith renders a metric name with matchers. A quoted metric name has to move
// inside the braces, so it cannot simply be prefixed onto them.
func selWith(metric string, matchers ...string) string {
	inner := strings.Join(matchers, ", ")
	if legacyNameRE.MatchString(metric) {
		return fmt.Sprintf("%s{%s}", metric, inner)
	}
	return fmt.Sprintf("{%s, %s}", strconv.Quote(metric), inner)
}

// schemaQuery builds the schema-aware selector for the later version.
func schemaQuery() string {
	return selWith(*newMetric,
		fmt.Sprintf("__semconv_url__=\"registry/%s\"", *newVer),
		fmt.Sprintf("__schema_url__=%q", *schema))
}

// eraSeries renders the series one era writes, as a selector the reader can paste.
func eraSeries(metric, tenantAttr, code string) string {
	return selWith(metric,
		fmt.Sprintf("%s=\"acme\"", lbl(tenantAttr)),
		fmt.Sprintf("%s=%s", lbl("http.response.status_code"), code))
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// writeEra writes the 200/404 series for one era under the given metric name
// over [start, end), advancing the shared counter value. tenantAttr is the
// era's name for the renamed attribute (user in 1.0.0, tenant in 1.1.0).
func writeEra(db *tsdb.DB, metric, tenantAttr string, start, end time.Time, interval time.Duration, value *float64) error {
	app := db.Appender(context.Background())
	for t := start; t.Before(end); t = t.Add(interval) {
		*value += 10
		for _, code := range []string{"200", "404"} {
			v := *value
			if code == "404" {
				v = *value * 0.1
			}
			lbls := labels.FromStrings(
				"__name__", metric,
				tenantAttr, "acme",
				"http.response.status_code", code,
				"instance", "myapp:8080",
			)
			if _, err := app.Append(0, lbls, t.UnixMilli(), v); err != nil {
				return fmt.Errorf("append sample: %w", err)
			}
		}
	}
	return app.Commit()
}

func run() error {
	flag.Parse()

	fmt.Printf("\n%s%s=== Versioned OTel Semantic Conventions Demo ===%s\n\n", colorBold, colorCyan, colorReset)

	// Determine TSDB directory.
	var tsdbDir string
	var cleanup func()

	if *dataDir != "" {
		// User-specified directory - don't delete on exit.
		tsdbDir = *dataDir
		cleanup = func() {}
		// Create directory if it doesn't exist.
		if err := os.MkdirAll(tsdbDir, 0o755); err != nil {
			return fmt.Errorf("create data dir: %w", err)
		}
	} else {
		// Temp directory - delete on exit.
		tmpDir, err := os.MkdirTemp("", "semconv-demo-")
		if err != nil {
			return fmt.Errorf("create temp dir: %w", err)
		}
		tsdbDir = tmpDir
		cleanup = func() { os.RemoveAll(tmpDir) }
	}
	defer cleanup()

	fmt.Printf("TSDB data directory: %s%s%s\n\n", colorYellow, tsdbDir, colorReset)

	// Create logger.
	logger := promslog.New(&promslog.Config{})

	// Open TSDB.
	db, err := tsdb.Open(tsdbDir, logger, nil, tsdb.DefaultOptions(), nil)
	if err != nil {
		return fmt.Errorf("open TSDB: %w", err)
	}
	defer db.Close()

	// Simulate a native-OTel metric renamed across semconv versions:
	// - Phase 1 (2h-1h ago): semconv 1.0.0, metric named "test.counter".
	// - Phase 2 (1h ago-now): semconv 1.1.0 renamed it to "test".
	now := time.Now()
	interval := 15 * time.Second
	value := 100.0

	// ===== Phase 1: semconv 1.0.0 era — test.counter (2h-1h ago) =====
	printPhase(1, fmt.Sprintf("Semconv %s era: metric %s", *oldVer, *oldMetric))
	fmt.Printf("The producer used semconv %s: metric %q with attribute %q\n", *oldVer, *oldMetric, *oldAttr)
	fmt.Print("Writing samples from 2 hours ago to 1 hour ago...\n\n")
	if err := writeEra(db, *oldMetric, *oldAttr, now.Add(-2*time.Hour), now.Add(-1*time.Hour), interval, &value); err != nil {
		return err
	}
	fmt.Printf("  %s[Written]%s %d samples each for %s\n\n", colorGreen, colorReset, int(time.Hour/interval), eraSeries(*oldMetric, *oldAttr, "\"200\"/\"404\""))

	// ===== Phase 2: semconv 1.1.0 era — renamed to test (1h ago-now) =====
	printPhase(2, fmt.Sprintf("Semconv %s era: renamed to %s", *newVer, *newMetric))
	fmt.Printf("Semconv %s renamed %q → %q and %q → %q. The same\n", *newVer, *oldMetric, *newMetric, *oldAttr, *newAttr)
	fmt.Printf("producer now writes %q with %q. Writing samples from 1 hour ago to now...\n\n", *newMetric, *newAttr)
	if err := writeEra(db, *newMetric, *newAttr, now.Add(-1*time.Hour), now, interval, &value); err != nil {
		return err
	}
	fmt.Printf("  %s[Written]%s %d samples each for %s\n\n", colorGreen, colorReset, int(time.Hour/interval), eraSeries(*newMetric, *newAttr, "\"200\"/\"404\""))

	// If populate-only mode, exit here.
	if *populateOnly {
		fmt.Printf("%s%s--- Data population complete ---%s\n\n", colorBold, colorGreen, colorReset)
		fmt.Printf("TSDB data written to: %s%s%s\n\n", colorYellow, tsdbDir, colorReset)
		fmt.Print("To query this data in the browser, run:\n")
		fmt.Printf("  %s./prometheus --storage.tsdb.path=%s --config.file=/dev/null --enable-feature=semconv-versioned-read%s\n\n", colorCyan, tsdbDir, colorReset)
		fmt.Print("Then open http://localhost:9090 and try these queries:\n\n")
		fmt.Printf("  %sThe Problem - the rename splits the series across two names:%s\n", colorYellow, colorReset)
		fmt.Printf("    %s%s%s   # Only the semconv %s era (2h-1h ago)\n", colorMagenta, sel(*oldMetric), colorReset, *oldVer)
		fmt.Printf("    %s%s%s   # Only the semconv %s era (1h-now)\n\n", colorMagenta, sel(*newMetric), colorReset, *newVer)
		fmt.Printf("  %sThe Solution - __schema_url__ walks the version renames:%s\n", colorGreen, colorReset)
		fmt.Printf("    %s%s%s   # Both eras under %q\n\n", colorMagenta, schemaQuery(), colorReset, *newMetric)
		if *oldAttr != *newAttr {
			fmt.Printf("  %sAttribute rename - __schema_url__ also normalises %s → %s:%s\n", colorGreen, *oldAttr, *newAttr, colorReset)
			fmt.Printf("    %ssum by (%s) (%s)%s   # %s %q folds into %q\n\n", colorMagenta, lbl(*newAttr), schemaQuery(), colorReset, *oldVer, *oldAttr, *newAttr)
		}
		return nil
	}

	// ===== Phase 3: Demonstrate the problem - the rename splits the series =====
	printPhase(3, "The Problem: a rename splits the series")

	semconvStorage := semconv.AwareStorage(db)
	opts := promql.EngineOpts{
		Logger:     logger,
		MaxSamples: 50000,
		Timeout:    time.Minute,
	}
	engine := promql.NewEngine(opts)
	ctx := context.Background()

	fmt.Print("After the rename, neither name alone covers the whole timeline:\n\n")
	runRangeQueryWithDetails(ctx, engine, db, now, sel(*oldMetric),
		fmt.Sprintf("Old (%s) name - only data from BEFORE the rename", *oldVer))
	runRangeQueryWithDetails(ctx, engine, db, now, sel(*newMetric),
		fmt.Sprintf("New (%s) name - only data from AFTER the rename", *newVer))
	fmt.Printf("  %s=> Neither query alone shows the complete picture!%s\n\n", colorYellow, colorReset)

	// ===== Phase 4: The schema-version solution - __schema_url__ =====
	printPhase(4, "The Solution: __schema_url__")

	fmt.Print("__semconv_url__ selects the registry version; __schema_url__ turns on\n")
	fmt.Print("schema-version fan-out, walking the schema's `versions` section to recover the\n")
	fmt.Print("metric's historical names and merging results under the requested version's name.\n\n")

	runRangeQueryWithDetails(ctx, engine, semconvStorage, now,
		schemaQuery(),
		fmt.Sprintf("Schema-aware query - spans the rename, unified under %q", *newMetric))
	fmt.Printf("  %s=> Complete coverage across the rename boundary at %s%s\n\n", colorGreen, now.Add(-1*time.Hour).Format("15:04"), colorReset)

	// ===== Phase 5: attribute-rename continuity. Only meaningful when an
	// attribute actually changed name between the two versions. =====
	if *oldAttr != *newAttr {
		printPhase(5, fmt.Sprintf("Attribute rename: %s → %s", *oldAttr, *newAttr))

		fmt.Printf("Semconv %s also renamed the attribute %q → %q. __schema_url__\n", *newVer, *oldAttr, *newAttr)
		fmt.Print("normalises historical attribute names too, so aggregating by the new name folds\n")
		fmt.Printf("the %s era (labelled %q) in rather than dropping it.\n\n", *oldVer, *oldAttr)

		runRangeQueryWithDetails(ctx, engine, semconvStorage, now,
			fmt.Sprintf("sum by (%s) (%s)", lbl(*newAttr), schemaQuery()),
			fmt.Sprintf("sum by (%s) - groups both eras under the canonical attribute name", *newAttr))
		fmt.Printf("  %s=> The %s %q series is grouped under %q, spanning the rename%s\n\n", colorGreen, *oldVer, *oldAttr, *newAttr, colorReset)
	}

	// ===== Summary =====
	fmt.Printf("\n%s%s--- Summary ---%s\n\n", colorBold, colorGreen, colorReset)
	fmt.Print("This demo simulated a producer (myapp:8080) whose metric was renamed\n")
	fmt.Print("across semantic-conventions versions:\n\n")
	fmt.Printf("  %s*%s semconv %s (2h-1h ago): %s\n", colorCyan, colorReset, *oldVer, eraSeries(*oldMetric, *oldAttr, "\"200\", ..."))
	fmt.Printf("  %s*%s semconv %s (1h ago-now): %s\n\n", colorCyan, colorReset, *newVer, eraSeries(*newMetric, *newAttr, "\"200\", ..."))
	fmt.Printf("  %s*%s Without __schema_url__: queries break at the rename, dashboards show gaps\n", colorYellow, colorReset)
	fmt.Printf("  %s*%s With __semconv_url__ + __schema_url__: one query spans the rename, unifying\n", colorGreen, colorReset)
	if *oldAttr != *newAttr {
		fmt.Printf("    both the metric name (%s) and the attribute name (%s)\n\n", *newMetric, *newAttr)
	} else {
		fmt.Printf("    the metric name (%s)\n\n", *newMetric)
	}

	return nil
}

func printPhase(n int, description string) {
	fmt.Printf("%s%s--- Phase %d: %s ---%s\n\n", colorBold, colorYellow, n, description, colorReset)
}

// queryStats summarizes a range-query result for the demo's display helpers.
type queryStats struct {
	series     int
	points     int
	minT, maxT int64
}

// execRange runs query over the demo's full ~3.5h window (wide enough to span
// both eras) and returns summary stats. It prints the query and description
// lines and any error; ok is false on error or an empty result.
func execRange(ctx context.Context, engine *promql.Engine, storage storage.Queryable, now time.Time, query, description string) (queryStats, bool) {
	fmt.Printf("  Query: %s%s%s\n", colorMagenta, query, colorReset)
	fmt.Printf("  %s\n", description)

	start := now.Add(-210 * time.Minute)
	end := now
	step := 5 * time.Minute

	q, err := engine.NewRangeQuery(ctx, storage, nil, query, start, end, step)
	if err != nil {
		fmt.Printf("  %s[Error]%s Failed to create query: %v\n\n", colorYellow, colorReset, err)
		return queryStats{}, false
	}
	result := q.Exec(ctx)
	if result.Err != nil {
		fmt.Printf("  %s[Error]%s Query failed: %v\n\n", colorYellow, colorReset, result.Err)
		return queryStats{}, false
	}

	matrix, ok := result.Value.(promql.Matrix)
	if !ok || len(matrix) == 0 {
		fmt.Printf("  %s[Result]%s No data returned\n\n", colorYellow, colorReset)
		return queryStats{}, false
	}

	stats := queryStats{series: len(matrix)}
	for _, series := range matrix {
		for _, point := range series.Floats {
			if stats.minT == 0 || point.T < stats.minT {
				stats.minT = point.T
			}
			if point.T > stats.maxT {
				stats.maxT = point.T
			}
			stats.points++
		}
	}
	return stats, true
}

// runRangeQueryWithDetails runs query and classifies whether the result covers
// data before, after, or spanning the rename boundary.
func runRangeQueryWithDetails(ctx context.Context, engine *promql.Engine, storage storage.Queryable, now time.Time, query, description string) {
	stats, ok := execRange(ctx, engine, storage, now, query, description)
	if !ok {
		return
	}

	renamePoint := now.Add(-1 * time.Hour).UnixMilli()
	minTimeStr := time.UnixMilli(stats.minT).Format("15:04")
	maxTimeStr := time.UnixMilli(stats.maxT).Format("15:04")
	renameStr := time.UnixMilli(renamePoint).Format("15:04")

	var coverage string
	switch {
	case stats.minT < renamePoint && stats.maxT > renamePoint:
		coverage = fmt.Sprintf("%s[FULL]%s %s to %s (spans the rename at %s)", colorGreen, colorReset, minTimeStr, maxTimeStr, renameStr)
	case stats.maxT <= renamePoint:
		coverage = fmt.Sprintf("%s[PARTIAL]%s %s to %s (only before the rename, ends at or before %s)", colorYellow, colorReset, minTimeStr, maxTimeStr, renameStr)
	default:
		coverage = fmt.Sprintf("%s[PARTIAL]%s %s to %s (only after the rename, starts at or after %s)", colorYellow, colorReset, minTimeStr, maxTimeStr, renameStr)
	}

	fmt.Printf("  [Result] %d series, %d data points\n", stats.series, stats.points)
	fmt.Printf("           Time coverage: %s\n\n", coverage)
}
