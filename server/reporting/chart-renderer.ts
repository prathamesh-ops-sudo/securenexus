/**
 * Server-side chart renderer for PDF reports.
 * Renders charts as vector graphics directly into PDFKit documents.
 * No external dependencies — uses PDFKit's built-in drawing primitives.
 */

const CHART_COLORS = [
  "#0040FF", // ATS Blue
  "#6366F1", // Indigo
  "#8B5CF6", // Violet
  "#EC4899", // Pink
  "#EF4444", // Red
  "#F97316", // Orange
  "#EAB308", // Yellow
  "#22C55E", // Green
  "#14B8A6", // Teal
  "#06B6D4", // Cyan
];

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#DC2626",
  high: "#F97316",
  medium: "#EAB308",
  low: "#22C55E",
  info: "#06B6D4",
};

export interface ChartDataPoint {
  label: string;
  value: number;
  color?: string;
}

export interface TrendPoint {
  label: string;
  value: number;
}

export interface ChartOptions {
  title?: string;
  width: number;
  height: number;
  showLegend?: boolean;
  showValues?: boolean;
  colorScheme?: "default" | "severity";
}

function getColor(index: number, scheme: "default" | "severity", label?: string): string {
  if (scheme === "severity" && label) {
    const lower = label.toLowerCase();
    if (SEVERITY_COLORS[lower]) return SEVERITY_COLORS[lower];
  }
  return CHART_COLORS[index % CHART_COLORS.length];
}

/**
 * Draw a horizontal bar chart into a PDFKit document
 */
export function drawBarChart(
  doc: PDFKit.PDFDocument,
  data: ChartDataPoint[],
  x: number,
  y: number,
  options: ChartOptions,
): number {
  const { width, height, title, showValues = true, colorScheme = "default" } = options;
  const barHeight = Math.min(24, (height - 40) / Math.max(data.length, 1));
  const gap = 6;
  const labelWidth = Math.min(120, width * 0.25);
  const barAreaWidth = width - labelWidth - (showValues ? 60 : 10);
  const maxVal = Math.max(...data.map((d) => d.value), 1);

  let currentY = y;

  if (title) {
    doc.font("Helvetica-Bold").fontSize(10).fillColor("#1a1a2e");
    doc.text(title, x, currentY, { width });
    currentY += 18;
  }

  for (let i = 0; i < data.length; i++) {
    const item = data[i];
    const barWidth = (item.value / maxVal) * barAreaWidth;
    const color = item.color || getColor(i, colorScheme, item.label);

    // Label
    doc.font("Helvetica").fontSize(8).fillColor("#64748b");
    doc.text(item.label, x, currentY + 4, { width: labelWidth - 8, lineBreak: false });

    // Bar
    const barX = x + labelWidth;
    doc.roundedRect(barX, currentY + 2, Math.max(barWidth, 2), barHeight - 4, 2).fill(color);

    // Value
    if (showValues) {
      doc.font("Helvetica-Bold").fontSize(8).fillColor("#1a1a2e");
      doc.text(String(item.value), barX + barWidth + 6, currentY + 4, { width: 50, lineBreak: false });
    }

    currentY += barHeight + gap;
  }

  return currentY;
}

/**
 * Draw a donut/pie chart into a PDFKit document
 */
export function drawDonutChart(
  doc: PDFKit.PDFDocument,
  data: ChartDataPoint[],
  x: number,
  y: number,
  options: ChartOptions,
): number {
  const { width, height, title, showLegend = true, colorScheme = "default" } = options;
  const radius = Math.min(width * 0.2, height * 0.35);
  const innerRadius = radius * 0.55;
  const centerX = x + (showLegend ? width * 0.3 : width / 2);
  const centerY = y + (title ? 20 : 0) + radius + 10;
  const total = data.reduce((sum, d) => sum + d.value, 0);

  let currentY = y;

  if (title) {
    doc.font("Helvetica-Bold").fontSize(10).fillColor("#1a1a2e");
    doc.text(title, x, currentY, { width });
    currentY += 18;
  }

  if (total === 0) {
    doc.font("Helvetica").fontSize(9).fillColor("#94a3b8");
    doc.text("No data available", x, centerY - 5, { width, align: "center" });
    return currentY + height;
  }

  // Draw arcs as filled wedges
  let startAngle = -Math.PI / 2;
  for (let i = 0; i < data.length; i++) {
    const item = data[i];
    const sliceAngle = (item.value / total) * 2 * Math.PI;
    const endAngle = startAngle + sliceAngle;
    const color = item.color || getColor(i, colorScheme, item.label);

    // Draw wedge using path
    doc.save();
    doc.fillColor(color);

    // Approximate arc with line segments
    const segments = Math.max(Math.ceil(sliceAngle / 0.1), 4);
    const angleStep = sliceAngle / segments;

    // Outer arc
    doc.moveTo(centerX + Math.cos(startAngle) * radius, centerY + Math.sin(startAngle) * radius);
    for (let s = 1; s <= segments; s++) {
      const angle = startAngle + s * angleStep;
      doc.lineTo(centerX + Math.cos(angle) * radius, centerY + Math.sin(angle) * radius);
    }
    // Line to inner arc end
    doc.lineTo(centerX + Math.cos(endAngle) * innerRadius, centerY + Math.sin(endAngle) * innerRadius);
    // Inner arc (reverse)
    for (let s = segments - 1; s >= 0; s--) {
      const angle = startAngle + s * angleStep;
      doc.lineTo(centerX + Math.cos(angle) * innerRadius, centerY + Math.sin(angle) * innerRadius);
    }
    doc.closePath();
    doc.fill();
    doc.restore();

    startAngle = endAngle;
  }

  // Center text
  doc.font("Helvetica-Bold").fontSize(16).fillColor("#1a1a2e");
  doc.text(String(total), centerX - 30, centerY - 12, { width: 60, align: "center" });
  doc.font("Helvetica").fontSize(7).fillColor("#64748b");
  doc.text("Total", centerX - 30, centerY + 6, { width: 60, align: "center" });

  // Legend
  if (showLegend) {
    const legendX = x + width * 0.6;
    let legendY = currentY + 10;
    for (let i = 0; i < data.length; i++) {
      const item = data[i];
      const color = item.color || getColor(i, colorScheme, item.label);
      const pct = total > 0 ? Math.round((item.value / total) * 100) : 0;

      doc.rect(legendX, legendY + 2, 10, 10).fill(color);
      doc.font("Helvetica").fontSize(8).fillColor("#1a1a2e");
      doc.text(`${item.label} (${pct}%)`, legendX + 16, legendY + 2, { width: width * 0.35, lineBreak: false });
      doc.font("Helvetica").fontSize(8).fillColor("#64748b");
      doc.text(String(item.value), legendX + 16, legendY + 13, { width: width * 0.35, lineBreak: false });
      legendY += 26;
    }
  }

  return currentY + height;
}

/**
 * Draw a sparkline / trend chart into a PDFKit document
 */
export function drawTrendChart(
  doc: PDFKit.PDFDocument,
  data: TrendPoint[],
  x: number,
  y: number,
  options: ChartOptions,
): number {
  const { width, height, title, showValues = true } = options;
  const chartPadding = { top: title ? 30 : 10, bottom: 30, left: 40, right: 20 };
  const chartWidth = width - chartPadding.left - chartPadding.right;
  const chartHeight = height - chartPadding.top - chartPadding.bottom;
  const chartX = x + chartPadding.left;
  const chartY = y + chartPadding.top;

  let currentY = y;

  if (title) {
    doc.font("Helvetica-Bold").fontSize(10).fillColor("#1a1a2e");
    doc.text(title, x, currentY, { width });
    currentY += 18;
  }

  if (data.length === 0) {
    doc.font("Helvetica").fontSize(9).fillColor("#94a3b8");
    doc.text("No trend data", x, chartY + chartHeight / 2, { width, align: "center" });
    return y + height;
  }

  const maxVal = Math.max(...data.map((d) => d.value), 1);
  const stepX = chartWidth / Math.max(data.length - 1, 1);

  // Y-axis gridlines
  const gridLines = 4;
  for (let i = 0; i <= gridLines; i++) {
    const gridY = chartY + (chartHeight / gridLines) * i;
    const gridVal = Math.round(maxVal - (maxVal / gridLines) * i);
    doc
      .moveTo(chartX, gridY)
      .lineTo(chartX + chartWidth, gridY)
      .strokeColor("#E2E8F0")
      .lineWidth(0.5)
      .stroke();
    doc.font("Helvetica").fontSize(7).fillColor("#94a3b8");
    doc.text(String(gridVal), x, gridY - 4, { width: chartPadding.left - 6, align: "right" });
  }

  // Area fill
  doc.save();
  doc.moveTo(chartX, chartY + chartHeight);
  for (let i = 0; i < data.length; i++) {
    const px = chartX + i * stepX;
    const py = chartY + chartHeight - (data[i].value / maxVal) * chartHeight;
    doc.lineTo(px, py);
  }
  doc.lineTo(chartX + (data.length - 1) * stepX, chartY + chartHeight);
  doc.closePath();
  doc.fillColor("#0040FF").opacity(0.08).fill();
  doc.restore();

  // Line
  doc.save();
  doc.strokeColor("#0040FF").lineWidth(1.5);
  for (let i = 0; i < data.length; i++) {
    const px = chartX + i * stepX;
    const py = chartY + chartHeight - (data[i].value / maxVal) * chartHeight;
    if (i === 0) {
      doc.moveTo(px, py);
    } else {
      doc.lineTo(px, py);
    }
  }
  doc.stroke();
  doc.restore();

  // Points
  for (let i = 0; i < data.length; i++) {
    const px = chartX + i * stepX;
    const py = chartY + chartHeight - (data[i].value / maxVal) * chartHeight;
    doc.circle(px, py, 3).fill("#FFFFFF");
    doc.circle(px, py, 3).strokeColor("#0040FF").lineWidth(1.5).stroke();
    doc.circle(px, py, 2).fill("#0040FF");
  }

  // X-axis labels
  const labelInterval = Math.max(1, Math.floor(data.length / 7));
  for (let i = 0; i < data.length; i += labelInterval) {
    const px = chartX + i * stepX;
    doc.font("Helvetica").fontSize(6.5).fillColor("#94a3b8");
    doc.text(data[i].label, px - 20, chartY + chartHeight + 6, { width: 40, align: "center" });
  }

  // Show latest value
  if (showValues && data.length > 0) {
    const last = data[data.length - 1];
    const px = chartX + (data.length - 1) * stepX;
    const py = chartY + chartHeight - (last.value / maxVal) * chartHeight;
    doc.font("Helvetica-Bold").fontSize(8).fillColor("#0040FF");
    doc.text(String(last.value), px + 6, py - 4, { width: 40, lineBreak: false });
  }

  return y + height;
}

/**
 * Draw KPI cards in a grid layout
 */
export function drawKpiCards(
  doc: PDFKit.PDFDocument,
  kpis: Array<{
    label: string;
    value: string | number;
    trend?: "up" | "down" | "flat";
    delta?: string;
    color?: string;
  }>,
  x: number,
  y: number,
  contentWidth: number,
): number {
  const colCount = Math.min(kpis.length, 4);
  const cardWidth = (contentWidth - (colCount - 1) * 10) / colCount;
  const cardHeight = 64;

  let maxY = y;

  for (let i = 0; i < kpis.length; i++) {
    const col = i % colCount;
    const row = Math.floor(i / colCount);
    const cardX = x + col * (cardWidth + 10);
    const cardY = y + row * (cardHeight + 8);

    // Check page break
    if (cardY + cardHeight > doc.page.height - 100) {
      doc.addPage();
      return drawKpiCards(doc, kpis.slice(i), x, doc.page.margins.top + 60, contentWidth);
    }

    // Card background
    doc.roundedRect(cardX, cardY, cardWidth, cardHeight, 4).fill("#F8FAFC");
    doc.roundedRect(cardX, cardY, cardWidth, cardHeight, 4).strokeColor("#E2E8F0").lineWidth(0.5).stroke();

    // Left accent
    const accentColor = kpis[i].color || "#0040FF";
    doc.rect(cardX, cardY + 4, 3, cardHeight - 8).fill(accentColor);

    // Label
    doc.font("Helvetica").fontSize(7.5).fillColor("#64748b");
    doc.text(kpis[i].label, cardX + 12, cardY + 8, { width: cardWidth - 20 });

    // Value
    doc.font("Helvetica-Bold").fontSize(18).fillColor("#1a1a2e");
    doc.text(String(kpis[i].value), cardX + 12, cardY + 24, { width: cardWidth - 20 });

    // Delta / Trend indicator
    if (kpis[i].delta) {
      const trendColor = kpis[i].trend === "up" ? "#22C55E" : kpis[i].trend === "down" ? "#EF4444" : "#64748b";
      const arrow = kpis[i].trend === "up" ? "▲" : kpis[i].trend === "down" ? "▼" : "—";
      doc.font("Helvetica").fontSize(7).fillColor(trendColor);
      doc.text(`${arrow} ${kpis[i].delta}`, cardX + 12, cardY + 48, { width: cardWidth - 20 });
    }

    maxY = Math.max(maxY, cardY + cardHeight + 8);
  }

  return maxY;
}

/**
 * Draw a gauge/score indicator
 */
export function drawScoreGauge(
  doc: PDFKit.PDFDocument,
  score: number,
  maxScore: number,
  label: string,
  x: number,
  y: number,
  size: number,
): number {
  const centerX = x + size / 2;
  const centerY = y + size / 2;
  const radius = size * 0.4;
  const pct = Math.min(score / maxScore, 1);

  // Background circle
  doc.circle(centerX, centerY, radius).fill("#F1F5F9");
  doc.circle(centerX, centerY, radius).strokeColor("#E2E8F0").lineWidth(8).stroke();

  // Progress arc
  const color = pct >= 0.8 ? "#22C55E" : pct >= 0.5 ? "#EAB308" : "#EF4444";
  const startAngle = -Math.PI / 2;
  const endAngle = startAngle + pct * 2 * Math.PI;
  const segments = Math.max(Math.ceil(pct * 40), 4);
  const angleStep = (endAngle - startAngle) / segments;

  doc.save();
  doc.strokeColor(color).lineWidth(8).lineCap("round");
  doc.moveTo(centerX + Math.cos(startAngle) * radius, centerY + Math.sin(startAngle) * radius);
  for (let s = 1; s <= segments; s++) {
    const a = startAngle + s * angleStep;
    doc.lineTo(centerX + Math.cos(a) * radius, centerY + Math.sin(a) * radius);
  }
  doc.stroke();
  doc.restore();

  // Score text
  doc.font("Helvetica-Bold").fontSize(18).fillColor("#1a1a2e");
  doc.text(`${Math.round(pct * 100)}%`, centerX - 25, centerY - 10, { width: 50, align: "center" });

  // Label
  doc.font("Helvetica").fontSize(8).fillColor("#64748b");
  doc.text(label, x, y + size - 4, { width: size, align: "center" });

  return y + size + 10;
}
