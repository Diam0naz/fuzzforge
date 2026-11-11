// The Fuzzforge mark: the F built from bars of tempered steel, with the
// middle arm displaced in oxide red, the input that broke something.
// Geometry and colours come from brand/make.py; keep them in step.
const BARS: [number, number, number, string][] = [
  [1, 6, 36, "#a8822f"],
  [9, 6, 10, "#8f6226"],
  [17, 10, 28, "#a3362e"],
  [25, 6, 10, "#5b4f9b"],
  [33, 6, 10, "#3d57a8"],
  [41, 6, 10, "#2a4a9e"],
];

export function Mark({ size = 28 }: { size?: number }) {
  return (
    <svg className="mark" viewBox="0 0 48 48" width={size} height={size} aria-hidden="true" focusable="false">
      {BARS.map(([y, x, w, fill]) => (
        <rect key={y} x={x} y={y} width={w} height={6} fill={fill} />
      ))}
    </svg>
  );
}
