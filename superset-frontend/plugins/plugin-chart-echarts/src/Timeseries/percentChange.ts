/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
import { DataRecord } from '@superset-ui/core';

/**
 * Rebases every non-x column of a timeseries result to its percent change
 * from that column's first non-null value, restoring the view the legacy
 * nvd3 "Time-series Percent Change" chart computed in the renderer:
 * y' = y / y0 - 1. Columns whose baseline is 0 (or missing) yield nulls
 * since a percent change from zero is undefined.
 */
export function rebaseToPercentChange(
  records: DataRecord[],
  xAxis: string,
): DataRecord[] {
  const baselines: Record<string, number> = {};
  records.forEach(record => {
    Object.entries(record).forEach(([key, value]) => {
      if (
        key !== xAxis &&
        !(key in baselines) &&
        typeof value === 'number' &&
        !Number.isNaN(value)
      ) {
        baselines[key] = value;
      }
    });
  });

  return records.map(record => {
    const rebased: DataRecord = { [xAxis]: record[xAxis] };
    Object.entries(record).forEach(([key, value]) => {
      if (key === xAxis) return;
      const baseline = baselines[key];
      rebased[key] =
        typeof value === 'number' &&
        !Number.isNaN(value) &&
        baseline !== undefined &&
        baseline !== 0
          ? value / baseline - 1
          : null;
    });
    return rebased;
  });
}

export type SeriesDataPoint = [number | string, number | null];

/**
 * Re-indexes already-rebased series data to a new baseline x. Because
 * percent-change rebasing is composable, v' = (1 + v) / (1 + vk) - 1
 * derives the new view directly from the currently displayed values,
 * where vk is the series value at the nearest x at or before the new
 * baseline (falling back to the first non-null point). Numeric x values
 * compare by magnitude; category x values compare by their position in
 * the series, since their labels carry no meaningful order.
 */
export function rebaseSeriesData(
  data: SeriesDataPoint[],
  baselineX: number | string,
): SeriesDataPoint[] {
  const baselineIndex =
    typeof baselineX === 'string'
      ? data.findIndex(([x]) => x === baselineX)
      : -1;
  const isAtOrBeforeBaseline = (x: number | string, index: number) =>
    typeof baselineX === 'string'
      ? baselineIndex !== -1 && index <= baselineIndex
      : typeof x === 'number' && x <= baselineX;
  // the non-null point with the largest x at or before the baseline,
  // falling back to the first non-null point
  let baselineValue: number | null = null;
  data.forEach(([x, y], index) => {
    if (y == null) return;
    if (isAtOrBeforeBaseline(x, index) || baselineValue === null) {
      baselineValue = y;
    }
  });
  if (baselineValue === null || baselineValue === -1) {
    return data.map(([x]) => [x, null]);
  }
  const divisor = 1 + baselineValue;
  return data.map(([x, y]) => [x, y == null ? null : (1 + y) / divisor - 1]);
}

/**
 * Snaps a dragged x position to the nearest available data x. Time/value
 * axes report a continuous pixel-derived number, so the nearest point is
 * found by numeric distance. Category axes report either the category
 * label or its ordinal index (ECharts' `convertFromPixel` returns the
 * index), so a label is validated against the known x values and an index
 * is resolved positionally, clamped to the axis' range. Labels that don't
 * match any known x fall back to the first one.
 */
export function snapToNearestX(
  xs: (number | string)[],
  target: number | string,
): number | string | undefined {
  if (xs.length === 0) return undefined;
  if (typeof target === 'string') {
    return xs.includes(target) ? target : xs[0];
  }
  const numericXs = xs.filter((x): x is number => typeof x === 'number');
  if (numericXs.length === 0) {
    if (Number.isNaN(target)) return undefined;
    const index = Math.min(xs.length - 1, Math.max(0, Math.round(target)));
    return xs[index];
  }
  return numericXs.reduce((best, x) =>
    Math.abs(x - target) < Math.abs(best - target) ? x : best,
  );
}
