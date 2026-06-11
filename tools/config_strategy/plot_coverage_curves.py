#!/usr/bin/env python3
import argparse
import csv
import html
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Sequence, Tuple


@dataclass(frozen=True)
class Sample:
    sample_time_utc: str
    elapsed_sec: float
    unique_pcs: int


@dataclass(frozen=True)
class Curve:
    label: str
    path: Path
    samples: List[Sample]

    @property
    def final_sample(self) -> Sample:
        return self.samples[-1]

    @property
    def elapsed_hours(self) -> float:
        return self.final_sample.elapsed_sec / 3600.0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render one or more syzkaller coverage_curve.csv files into a standalone HTML chart."
    )
    parser.add_argument(
        "--curve",
        action="append",
        required=True,
        help="Curve spec in the form label=path/to/coverage_curve.csv or label=path/to/result_dir",
    )
    parser.add_argument("--out", required=True, help="Output HTML path")
    parser.add_argument(
        "--title",
        default="Coverage Over Time",
        help="Chart title shown in the HTML report",
    )
    return parser.parse_args()


def parse_curve_spec(spec: str) -> Tuple[str, Path]:
    label, sep, raw_path = spec.partition("=")
    if not sep or not label.strip() or not raw_path.strip():
        raise ValueError(f"invalid --curve spec: {spec!r}")
    return label.strip(), Path(raw_path.strip()).expanduser()


def resolve_curve_path(path: Path) -> Path:
    if path.is_file():
        return path

    candidates = [
        path / "coverage_curve.csv",
        path / "syzkaller" / "coverage_curve.csv",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"could not locate coverage_curve.csv under {path}")


def load_curve(label: str, path: Path) -> Curve:
    curve_path = resolve_curve_path(path)
    samples: List[Sample] = []
    with curve_path.open(encoding="utf-8", newline="") as fp:
        reader = csv.DictReader(fp)
        for row in reader:
            samples.append(
                Sample(
                    sample_time_utc=row["sample_time_utc"].strip(),
                    elapsed_sec=float(row["elapsed_sec"]),
                    unique_pcs=int(row["unique_pcs"]),
                )
            )
    if not samples:
        raise ValueError(f"{curve_path} does not contain any samples")
    return Curve(label=label, path=curve_path.resolve(), samples=samples)


def nice_step(span: float, target_ticks: int) -> float:
    if span <= 0:
        return 1.0
    raw_step = span / max(target_ticks, 1)
    exponent = math.floor(math.log10(raw_step))
    fraction = raw_step / (10 ** exponent)
    if fraction <= 1:
        nice_fraction = 1
    elif fraction <= 2:
        nice_fraction = 2
    elif fraction <= 5:
        nice_fraction = 5
    else:
        nice_fraction = 10
    return nice_fraction * (10 ** exponent)


def nice_time_step(span_seconds: float, target_ticks: int) -> float:
    preferred_steps = [
        1800.0,
        3600.0,
        7200.0,
        10800.0,
        14400.0,
        21600.0,
        28800.0,
        43200.0,
    ]
    raw_step = span_seconds / max(target_ticks, 1)
    for step in preferred_steps:
        if step >= raw_step:
            return step
    return preferred_steps[-1]


def format_pcs(value: float) -> str:
    if value >= 1000:
        return f"{value / 1000:.1f}k"
    return f"{value:.0f}"


def format_hours(seconds: float) -> str:
    return f"{seconds / 3600.0:.1f}h"


def to_svg_x(value: float, x_min: float, x_max: float, chart_left: float, chart_width: float) -> float:
    if x_max <= x_min:
        return chart_left
    return chart_left + (value - x_min) / (x_max - x_min) * chart_width


def to_svg_y(value: float, y_min: float, y_max: float, chart_top: float, chart_height: float) -> float:
    if y_max <= y_min:
        return chart_top + chart_height
    return chart_top + chart_height - (value - y_min) / (y_max - y_min) * chart_height


def build_svg(curves: Sequence[Curve], title: str) -> str:
    width = 1240
    height = 760
    margin_left = 92
    margin_right = 220
    margin_top = 76
    margin_bottom = 80
    chart_left = margin_left
    chart_top = margin_top
    chart_width = width - margin_left - margin_right
    chart_height = height - margin_top - margin_bottom

    x_min = 0.0
    x_max = max(curve.final_sample.elapsed_sec for curve in curves)
    all_pcs = [sample.unique_pcs for curve in curves for sample in curve.samples]
    raw_y_min = min(all_pcs)
    raw_y_max = max(all_pcs)
    y_padding = max((raw_y_max - raw_y_min) * 0.08, 500)
    y_min = max(0.0, math.floor((raw_y_min - y_padding) / 1000.0) * 1000.0)
    y_max = math.ceil((raw_y_max + y_padding) / 1000.0) * 1000.0
    if y_max <= y_min:
        y_max = y_min + 1000.0

    palette = [
        "#0f766e",
        "#c2410c",
        "#1d4ed8",
        "#b91c1c",
        "#6d28d9",
        "#0f172a",
    ]
    x_step = nice_time_step(x_max, 8)
    y_step = nice_step(y_max - y_min, 6)

    pieces: List[str] = []
    pieces.append(
        f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
        'xmlns="http://www.w3.org/2000/svg" role="img">'
    )
    pieces.append(f'<title>{html.escape(title)}</title>')
    pieces.append('<rect width="100%" height="100%" fill="#fffdf7" />')
    pieces.append(
        f'<text x="{chart_left}" y="34" font-size="26" font-family="Georgia, serif" fill="#111827">{html.escape(title)}</text>'
    )
    pieces.append(
        f'<text x="{chart_left}" y="58" font-size="13" font-family="ui-monospace, monospace" fill="#4b5563">'
        f'X axis: elapsed time | Y axis: unique PCs (zoomed to observed range {int(y_min)} - {int(y_max)})'
        "</text>"
    )

    x_tick = 0.0
    while x_tick <= x_max + x_step * 0.5:
        x = to_svg_x(min(x_tick, x_max), x_min, x_max, chart_left, chart_width)
        pieces.append(
            f'<line x1="{x:.2f}" y1="{chart_top}" x2="{x:.2f}" y2="{chart_top + chart_height}" '
            'stroke="#e5e7eb" stroke-width="1" />'
        )
        pieces.append(
            f'<text x="{x:.2f}" y="{chart_top + chart_height + 26}" text-anchor="middle" '
            'font-size="12" font-family="ui-monospace, monospace" fill="#6b7280">'
            f"{html.escape(format_hours(min(x_tick, x_max)))}"
            "</text>"
        )
        x_tick += x_step

    y_tick = math.ceil(y_min / y_step) * y_step
    while y_tick <= y_max + y_step * 0.5:
        y = to_svg_y(min(y_tick, y_max), y_min, y_max, chart_top, chart_height)
        pieces.append(
            f'<line x1="{chart_left}" y1="{y:.2f}" x2="{chart_left + chart_width}" y2="{y:.2f}" '
            'stroke="#e5e7eb" stroke-width="1" />'
        )
        pieces.append(
            f'<text x="{chart_left - 14}" y="{y + 4:.2f}" text-anchor="end" '
            'font-size="12" font-family="ui-monospace, monospace" fill="#6b7280">'
            f"{html.escape(format_pcs(min(y_tick, y_max)))}"
            "</text>"
        )
        y_tick += y_step

    pieces.append(
        f'<line x1="{chart_left}" y1="{chart_top + chart_height}" x2="{chart_left + chart_width}" '
        f'y2="{chart_top + chart_height}" stroke="#111827" stroke-width="1.5" />'
    )
    pieces.append(
        f'<line x1="{chart_left}" y1="{chart_top}" x2="{chart_left}" y2="{chart_top + chart_height}" '
        'stroke="#111827" stroke-width="1.5" />'
    )

    legend_x = chart_left + chart_width + 28
    legend_y = chart_top + 8

    for index, curve in enumerate(curves):
        color = palette[index % len(palette)]
        points = " ".join(
            f"{to_svg_x(sample.elapsed_sec, x_min, x_max, chart_left, chart_width):.2f},"
            f"{to_svg_y(sample.unique_pcs, y_min, y_max, chart_top, chart_height):.2f}"
            for sample in curve.samples
        )
        pieces.append(
            f'<polyline points="{points}" fill="none" stroke="{color}" stroke-width="2.8" '
            'stroke-linejoin="round" stroke-linecap="round">'
            f"<title>{html.escape(curve.label)}: final {curve.final_sample.unique_pcs} PCs</title>"
            "</polyline>"
        )

        final_x = to_svg_x(curve.final_sample.elapsed_sec, x_min, x_max, chart_left, chart_width)
        final_y = to_svg_y(curve.final_sample.unique_pcs, y_min, y_max, chart_top, chart_height)
        label_y = final_y + (index - (len(curves) - 1) / 2.0) * 22.0
        pieces.append(
            f'<circle cx="{final_x:.2f}" cy="{final_y:.2f}" r="4.5" fill="{color}" stroke="#fffdf7" stroke-width="2" />'
        )
        pieces.append(
            f'<line x1="{final_x + 6:.2f}" y1="{final_y:.2f}" x2="{final_x + 22:.2f}" y2="{label_y:.2f}" '
            f'stroke="{color}" stroke-width="1.5" />'
        )
        pieces.append(
            f'<rect x="{final_x + 22:.2f}" y="{label_y - 12:.2f}" width="154" height="24" rx="6" '
            'fill="#ffffff" fill-opacity="0.92" stroke="#d1d5db" />'
        )
        pieces.append(
            f'<text x="{final_x + 30:.2f}" y="{label_y + 5:.2f}" font-size="12.5" '
            'font-family="ui-monospace, monospace" fill="#111827">'
            f"{html.escape(curve.label)}: {curve.final_sample.unique_pcs}"
            "</text>"
        )

        row_y = legend_y + index * 58
        pieces.append(
            f'<line x1="{legend_x}" y1="{row_y}" x2="{legend_x + 28}" y2="{row_y}" stroke="{color}" stroke-width="4" />'
        )
        pieces.append(
            f'<text x="{legend_x + 38}" y="{row_y + 5}" font-size="13" font-family="system-ui, sans-serif" fill="#111827">'
            f"{html.escape(curve.label)}"
            "</text>"
        )
        pieces.append(
            f'<text x="{legend_x + 38}" y="{row_y + 23}" font-size="12" font-family="ui-monospace, monospace" fill="#4b5563">'
            f"{curve.final_sample.unique_pcs} PCs | {curve.elapsed_hours:.2f}h"
            "</text>"
        )

    pieces.append("</svg>")
    return "\n".join(pieces)


def build_summary_rows(curves: Sequence[Curve]) -> str:
    baseline = curves[0].final_sample.unique_pcs
    rows = []
    for curve in curves:
        delta = curve.final_sample.unique_pcs - baseline
        delta_text = f"{delta:+d}" if curve is not curves[0] else "baseline"
        rows.append(
            "<tr>"
            f"<td>{html.escape(curve.label)}</td>"
            f"<td>{curve.final_sample.unique_pcs}</td>"
            f"<td>{curve.elapsed_hours:.2f}</td>"
            f"<td>{len(curve.samples)}</td>"
            f"<td>{html.escape(delta_text)}</td>"
            f"<td><code>{html.escape(str(curve.path))}</code></td>"
            "</tr>"
        )
    return "\n".join(rows)


def build_html(curves: Sequence[Curve], title: str) -> str:
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    svg = build_svg(curves, title)
    summary_rows = build_summary_rows(curves)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)}</title>
  <style>
    :root {{
      --bg: #f6f3eb;
      --panel: #fffdf7;
      --ink: #111827;
      --muted: #4b5563;
      --line: #d6d3d1;
      --accent: #0f766e;
    }}
    body {{
      margin: 0;
      padding: 32px;
      background:
        radial-gradient(circle at top left, rgba(15, 118, 110, 0.08), transparent 28%),
        linear-gradient(180deg, #faf7f0 0%, var(--bg) 100%);
      color: var(--ink);
      font-family: "Segoe UI", "PingFang SC", "Noto Sans SC", sans-serif;
    }}
    main {{
      max-width: 1400px;
      margin: 0 auto;
    }}
    h1 {{
      margin: 0 0 8px 0;
      font-size: 30px;
      line-height: 1.2;
    }}
    p {{
      margin: 0;
      color: var(--muted);
      line-height: 1.5;
    }}
    .panel {{
      margin-top: 22px;
      padding: 18px 20px;
      border: 1px solid rgba(214, 211, 209, 0.85);
      border-radius: 18px;
      background: rgba(255, 253, 247, 0.92);
      box-shadow: 0 10px 30px rgba(17, 24, 39, 0.06);
      overflow-x: auto;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
    }}
    th, td {{
      padding: 10px 12px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
    }}
    th {{
      font-size: 12px;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      color: var(--muted);
    }}
    code {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
      white-space: nowrap;
    }}
    .footnote {{
      margin-top: 12px;
      font-size: 12px;
      color: var(--muted);
    }}
  </style>
</head>
<body>
  <main>
    <h1>{html.escape(title)}</h1>
    <p>Generated at {generated_at}. Input curves are compared by elapsed time using the original syzkaller coverage samples.</p>
    <section class="panel">
      {svg}
    </section>
    <section class="panel">
      <table>
        <thead>
          <tr>
            <th>Label</th>
            <th>Final PCs</th>
            <th>Hours</th>
            <th>Samples</th>
            <th>Vs First Curve</th>
            <th>Source</th>
          </tr>
        </thead>
        <tbody>
          {summary_rows}
        </tbody>
      </table>
      <p class="footnote">The Y axis is intentionally zoomed to the observed PC range so differences between strategies stay visible.</p>
    </section>
  </main>
</body>
</html>
"""


def main() -> None:
    args = parse_args()
    curves = [load_curve(*parse_curve_spec(spec)) for spec in args.curve]
    output_path = Path(args.out).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(build_html(curves, args.title), encoding="utf-8")
    print(f"wrote {output_path}")


if __name__ == "__main__":
    main()
