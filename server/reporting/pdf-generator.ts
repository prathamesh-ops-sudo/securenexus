/**
 * Advanced PDF Report Generator
 * Extends pdfkit with embedded charts, compliance templates,
 * executive dashboards, white-label MSSP support, and financial impact.
 */
import PDFDocument from "pdfkit";
import path from "path";
import fs from "fs";
import {
  drawBarChart,
  drawDonutChart,
  drawTrendChart,
  drawKpiCards,
  drawScoreGauge,
  type ChartDataPoint,
  type TrendPoint,
} from "./chart-renderer";

// ─── Brand Colors ────────────────────────────────────────────────────────────
const ATS_BLUE = "#0040FF";
const HEADER_BG = "#F0F4FF";
const TABLE_HEADER_BG = "#1a1a2e";
const TABLE_HEADER_TEXT = "#FFFFFF";
const TABLE_ALT_ROW = "#F8F9FC";
const TEXT_PRIMARY = "#1a1a2e";
const TEXT_SECONDARY = "#64748b";
const BORDER_COLOR = "#E2E8F0";

// ─── Interfaces ──────────────────────────────────────────────────────────────

export interface AdvancedReportSection {
  title: string;
  type:
    | "kpi"
    | "bar_chart"
    | "donut_chart"
    | "trend_chart"
    | "table"
    | "summary"
    | "score_gauge"
    | "text"
    | "financial_impact";
  data?: Record<string, unknown>;
  chartData?: ChartDataPoint[];
  trendData?: TrendPoint[];
  kpis?: Array<{
    label: string;
    value: string | number;
    trend?: "up" | "down" | "flat";
    delta?: string;
    color?: string;
  }>;
  columns?: string[];
  rows?: unknown[][];
  score?: number;
  maxScore?: number;
  scoreLabel?: string;
  text?: string;
  financialData?: FinancialImpactData;
}

export interface FinancialImpactData {
  annualRiskExposure: number;
  mitigatedRisk: number;
  residualRisk: number;
  costOfBreach: number;
  roiPercentage: number;
  riskItems: Array<{ category: string; exposure: number; probability: number; annualizedLoss: number }>;
}

export interface AdvancedReportData {
  title: string;
  subtitle?: string;
  generatedAt: string;
  reportType: string;
  orgId: string | null;
  sections: AdvancedReportSection[];
}

export interface WhiteLabelConfig {
  companyName: string;
  companyTagline?: string;
  logoPath?: string;
  primaryColor?: string;
  accentColor?: string;
  footerText?: string;
  confidential?: boolean;
  generatedBy?: string;
}

// ─── Logo Resolution ─────────────────────────────────────────────────────────

function getDefaultLogoPath(): string | null {
  const candidates = [
    path.join(process.cwd(), "client", "public", "ats-logo.png"),
    path.join(process.cwd(), "dist", "public", "ats-logo.png"),
  ];
  for (const p of candidates) {
    if (fs.existsSync(p)) return p;
  }
  return null;
}

// ─── Main Generator ──────────────────────────────────────────────────────────

export function generateAdvancedPdf(data: AdvancedReportData, whiteLabel?: WhiteLabelConfig): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    try {
      const brandColor = whiteLabel?.primaryColor || ATS_BLUE;
      const companyName = whiteLabel?.companyName || "Arica Tech Solutions";
      const logoPath = whiteLabel?.logoPath || getDefaultLogoPath();
      const confidential = whiteLabel?.confidential ?? false;

      const doc = new PDFDocument({
        size: "A4",
        margins: { top: 80, bottom: 80, left: 50, right: 50 },
        bufferPages: true,
        info: {
          Title: data.title,
          Author: `${companyName} — SecureNexus Platform`,
          Subject: `${data.reportType} Report`,
          Creator: "SecureNexus Advanced Reporting Engine",
          Producer: companyName,
        },
      });

      const chunks: Buffer[] = [];
      doc.on("data", (chunk: Buffer) => chunks.push(chunk));
      doc.on("end", () => resolve(Buffer.concat(chunks)));
      doc.on("error", reject);

      const pageWidth = doc.page.width;
      const contentWidth = pageWidth - doc.page.margins.left - doc.page.margins.right;
      const marginLeft = doc.page.margins.left;

      // ═══════════════════════════════════════════════════════════════════════
      // COVER PAGE
      // ═══════════════════════════════════════════════════════════════════════
      drawCoverPage(doc, data, companyName, logoPath, brandColor, confidential, whiteLabel);

      // ═══════════════════════════════════════════════════════════════════════
      // TABLE OF CONTENTS
      // ═══════════════════════════════════════════════════════════════════════
      if (data.sections.length > 3) {
        doc.addPage();
        drawTableOfContents(doc, data, brandColor, contentWidth, marginLeft);
      }

      // ═══════════════════════════════════════════════════════════════════════
      // CONTENT PAGES
      // ═══════════════════════════════════════════════════════════════════════
      doc.addPage();

      for (let i = 0; i < data.sections.length; i++) {
        const section = data.sections[i];

        // Page break check
        if (doc.y > doc.page.height - 200) {
          doc.addPage();
        }

        drawSectionHeader(doc, section.title, i, brandColor, contentWidth, marginLeft);

        switch (section.type) {
          case "kpi":
            if (section.kpis) {
              doc.y = drawKpiCards(doc, section.kpis, marginLeft, doc.y, contentWidth);
            }
            break;

          case "bar_chart":
            if (section.chartData) {
              doc.y = drawBarChart(doc, section.chartData, marginLeft, doc.y, {
                width: contentWidth,
                height: 200,
                showValues: true,
                colorScheme: section.title.toLowerCase().includes("severity") ? "severity" : "default",
              });
            }
            break;

          case "donut_chart":
            if (section.chartData) {
              doc.y = drawDonutChart(doc, section.chartData, marginLeft, doc.y, {
                width: contentWidth,
                height: 200,
                showLegend: true,
                colorScheme: section.title.toLowerCase().includes("severity") ? "severity" : "default",
              });
            }
            break;

          case "trend_chart":
            if (section.trendData) {
              doc.y = drawTrendChart(doc, section.trendData, marginLeft, doc.y, {
                width: contentWidth,
                height: 180,
                showValues: true,
              });
            }
            break;

          case "score_gauge":
            if (section.score != null && section.maxScore) {
              doc.y = drawScoreGauge(
                doc,
                section.score,
                section.maxScore,
                section.scoreLabel || "Score",
                marginLeft + contentWidth / 2 - 60,
                doc.y,
                120,
              );
            }
            break;

          case "table":
            if (section.columns && section.rows) {
              drawTable(doc, section.columns, section.rows, contentWidth, marginLeft);
            }
            break;

          case "summary":
            if (section.data) {
              drawSummaryCards(doc, section.data, contentWidth, marginLeft);
            }
            break;

          case "text":
            if (section.text) {
              doc.font("Helvetica").fontSize(9).fillColor(TEXT_PRIMARY);
              doc.text(section.text, marginLeft, doc.y, { width: contentWidth });
            }
            break;

          case "financial_impact":
            if (section.financialData) {
              drawFinancialImpact(doc, section.financialData, contentWidth, marginLeft, brandColor);
            }
            break;
        }

        doc.moveDown(1.5);
      }

      // ═══════════════════════════════════════════════════════════════════════
      // HEADERS, FOOTERS, WATERMARKS
      // ═══════════════════════════════════════════════════════════════════════
      const totalPages = doc.bufferedPageRange().count;
      for (let i = 0; i < totalPages; i++) {
        doc.switchToPage(i);

        if (i === 0) {
          drawFooterLine(doc, i + 1, totalPages, companyName, confidential, brandColor);
          continue;
        }

        drawPageHeader(doc, data.title, data.generatedAt, logoPath, brandColor, confidential, companyName);
        drawFooterLine(doc, i + 1, totalPages, companyName, confidential, brandColor);

        if (confidential) {
          drawWatermark(doc);
        }
      }

      doc.end();
    } catch (err) {
      reject(err);
    }
  });
}

// ─── Cover Page ──────────────────────────────────────────────────────────────

function drawCoverPage(
  doc: PDFKit.PDFDocument,
  data: AdvancedReportData,
  companyName: string,
  logoPath: string | null,
  brandColor: string,
  confidential: boolean,
  whiteLabel?: WhiteLabelConfig,
): void {
  const pageWidth = doc.page.width;
  const contentWidth = pageWidth - doc.page.margins.left - doc.page.margins.right;
  const centerX = pageWidth / 2;

  // Top bar
  doc.rect(0, 0, pageWidth, 6).fill(brandColor);

  // Logo
  if (logoPath && fs.existsSync(logoPath)) {
    doc.image(logoPath, centerX - 60, 100, { width: 120 });
  }

  // Company name
  doc.font("Helvetica-Bold").fontSize(14).fillColor(brandColor);
  doc.text(companyName.toUpperCase(), 0, 240, { align: "center", width: pageWidth });

  const tagline = whiteLabel?.companyTagline || "Enterprise Security Platform";
  doc.font("Helvetica").fontSize(9).fillColor(TEXT_SECONDARY);
  doc.text(tagline, 0, 258, { align: "center", width: pageWidth });

  // Divider
  doc
    .moveTo(centerX - 100, 290)
    .lineTo(centerX + 100, 290)
    .strokeColor(brandColor)
    .lineWidth(1.5)
    .stroke();

  // Report title
  doc.font("Helvetica-Bold").fontSize(24).fillColor(TEXT_PRIMARY);
  doc.text(data.title, 0, 320, { align: "center", width: pageWidth });

  // Subtitle
  if (data.subtitle) {
    doc.font("Helvetica").fontSize(11).fillColor(TEXT_SECONDARY);
    doc.text(data.subtitle, 0, 355, { align: "center", width: pageWidth });
  }

  // Confidential banner
  if (confidential) {
    doc.rect(centerX - 80, 400, 160, 28).fill("#FEF2F2");
    doc
      .rect(centerX - 80, 400, 160, 28)
      .strokeColor("#DC2626")
      .lineWidth(1)
      .stroke();
    doc.font("Helvetica-Bold").fontSize(10).fillColor("#DC2626");
    doc.text("CONFIDENTIAL", 0, 407, { align: "center", width: pageWidth });
  }

  // Metadata
  const metaY = confidential ? 460 : 420;
  const metaX = doc.page.margins.left + 60;
  const metaLabelWidth = 120;

  const metaRows: [string, string][] = [
    ["Report Date", formatDate(data.generatedAt)],
    ["Report Type", data.reportType.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())],
    ["Organization", companyName],
  ];
  if (whiteLabel?.generatedBy) metaRows.push(["Generated By", whiteLabel.generatedBy]);
  metaRows.push(["Classification", confidential ? "Confidential" : "Internal Use Only"]);

  for (let i = 0; i < metaRows.length; i++) {
    const y = metaY + i * 22;
    doc.font("Helvetica-Bold").fontSize(9).fillColor(TEXT_SECONDARY);
    doc.text(metaRows[i][0] + ":", metaX, y, { width: metaLabelWidth });
    doc.font("Helvetica").fontSize(9).fillColor(TEXT_PRIMARY);
    doc.text(metaRows[i][1], metaX + metaLabelWidth, y, { width: contentWidth - metaLabelWidth - 60 });
  }

  // Bottom
  doc
    .moveTo(doc.page.margins.left, doc.page.height - 120)
    .lineTo(pageWidth - doc.page.margins.right, doc.page.height - 120)
    .strokeColor(BORDER_COLOR)
    .lineWidth(0.5)
    .stroke();

  const disclaimerText =
    whiteLabel?.footerText ||
    "This report was automatically generated by SecureNexus. The information contained herein is intended " +
      "for the designated recipients only. Unauthorized disclosure, copying, or distribution is strictly prohibited.";
  doc.font("Helvetica-Oblique").fontSize(7).fillColor(TEXT_SECONDARY);
  doc.text(disclaimerText, doc.page.margins.left, doc.page.height - 110, { align: "center", width: contentWidth });

  doc.rect(0, doc.page.height - 6, pageWidth, 6).fill(brandColor);
}

// ─── Table of Contents ───────────────────────────────────────────────────────

function drawTableOfContents(
  doc: PDFKit.PDFDocument,
  data: AdvancedReportData,
  brandColor: string,
  contentWidth: number,
  marginLeft: number,
): void {
  doc.font("Helvetica-Bold").fontSize(18).fillColor(TEXT_PRIMARY);
  doc.text("Table of Contents", marginLeft, doc.page.margins.top + 60, { width: contentWidth });
  doc.moveDown(1.5);

  for (let i = 0; i < data.sections.length; i++) {
    const section = data.sections[i];
    doc.font("Helvetica-Bold").fontSize(10).fillColor(brandColor);
    doc.text(`${i + 1}.`, marginLeft, doc.y, { continued: true, width: 20 });
    doc.font("Helvetica").fontSize(10).fillColor(TEXT_PRIMARY);
    doc.text(` ${section.title}`, { width: contentWidth - 20 });
    doc.moveDown(0.4);
  }
}

// ─── Section Header ──────────────────────────────────────────────────────────

function drawSectionHeader(
  doc: PDFKit.PDFDocument,
  title: string,
  index: number,
  brandColor: string,
  contentWidth: number,
  marginLeft: number,
): void {
  doc.rect(marginLeft, doc.y, 4, 18).fill(brandColor);
  doc.font("Helvetica-Bold").fontSize(13).fillColor(TEXT_PRIMARY);
  doc.text(`${index + 1}. ${title}`, marginLeft + 12, doc.y - 16, { width: contentWidth - 12 });
  doc.moveDown(0.5);
}

// ─── Summary Cards ───────────────────────────────────────────────────────────

function drawSummaryCards(
  doc: PDFKit.PDFDocument,
  data: Record<string, unknown>,
  contentWidth: number,
  marginLeft: number,
): void {
  const entries = Object.entries(data);
  const colCount = entries.length <= 4 ? 2 : 3;
  const cardWidth = (contentWidth - (colCount - 1) * 10) / colCount;
  const cardHeight = 52;

  for (let i = 0; i < entries.length; i++) {
    const col = i % colCount;
    const row = Math.floor(i / colCount);
    const x = marginLeft + col * (cardWidth + 10);
    const y = doc.y + row * (cardHeight + 8);

    if (y + cardHeight > doc.page.height - 100) {
      doc.addPage();
      doc.y = doc.page.margins.top + 60;
    }

    doc.roundedRect(x, y, cardWidth, cardHeight, 4).fill("#F8FAFC");
    doc.roundedRect(x, y, cardWidth, cardHeight, 4).strokeColor(BORDER_COLOR).lineWidth(0.5).stroke();
    doc.rect(x, y + 4, 3, cardHeight - 8).fill(ATS_BLUE);

    doc.font("Helvetica").fontSize(7.5).fillColor(TEXT_SECONDARY);
    doc.text(entries[i][0], x + 12, y + 10, { width: cardWidth - 20 });

    const val = entries[i][1];
    const valStr = val === null || val === undefined ? "—" : String(val);
    doc.font("Helvetica-Bold").fontSize(16).fillColor(TEXT_PRIMARY);
    doc.text(valStr, x + 12, y + 26, { width: cardWidth - 20 });
  }

  const totalRows = Math.ceil(entries.length / colCount);
  doc.y = doc.y + totalRows * (cardHeight + 8) + 4;
}

// ─── Table ───────────────────────────────────────────────────────────────────

function drawTable(
  doc: PDFKit.PDFDocument,
  columns: string[],
  rows: unknown[][],
  contentWidth: number,
  marginLeft: number,
): void {
  if (columns.length === 0) return;

  const colWidths = columns.map(() => contentWidth / columns.length);
  const rowHeight = 22;
  const headerHeight = 26;

  // Header
  let y = doc.y;
  doc.rect(marginLeft, y, contentWidth, headerHeight).fill(TABLE_HEADER_BG);
  let x = marginLeft;
  for (let c = 0; c < columns.length; c++) {
    doc.font("Helvetica-Bold").fontSize(8).fillColor(TABLE_HEADER_TEXT);
    doc.text(columns[c], x + 6, y + 7, { width: colWidths[c] - 12, lineBreak: false });
    x += colWidths[c];
  }
  y += headerHeight;

  // Rows
  for (let r = 0; r < rows.length; r++) {
    if (y + rowHeight > doc.page.height - 100) {
      doc.addPage();
      y = doc.page.margins.top + 60;

      // Re-draw header
      doc.rect(marginLeft, y, contentWidth, headerHeight).fill(TABLE_HEADER_BG);
      x = marginLeft;
      for (let c = 0; c < columns.length; c++) {
        doc.font("Helvetica-Bold").fontSize(8).fillColor(TABLE_HEADER_TEXT);
        doc.text(columns[c], x + 6, y + 7, { width: colWidths[c] - 12, lineBreak: false });
        x += colWidths[c];
      }
      y += headerHeight;
    }

    // Alternating row background
    if (r % 2 === 1) {
      doc.rect(marginLeft, y, contentWidth, rowHeight).fill(TABLE_ALT_ROW);
    }

    x = marginLeft;
    for (let c = 0; c < rows[r].length && c < columns.length; c++) {
      doc.font("Helvetica").fontSize(7.5).fillColor(TEXT_PRIMARY);
      const val = rows[r][c];
      doc.text(val === null || val === undefined ? "" : String(val), x + 6, y + 6, {
        width: colWidths[c] - 12,
        lineBreak: false,
      });
      x += colWidths[c];
    }

    // Bottom border
    doc
      .moveTo(marginLeft, y + rowHeight)
      .lineTo(marginLeft + contentWidth, y + rowHeight)
      .strokeColor(BORDER_COLOR)
      .lineWidth(0.25)
      .stroke();

    y += rowHeight;
  }

  doc.y = y + 4;
}

// ─── Financial Impact ────────────────────────────────────────────────────────

function drawFinancialImpact(
  doc: PDFKit.PDFDocument,
  data: FinancialImpactData,
  contentWidth: number,
  marginLeft: number,
  brandColor: string,
): void {
  const formatCurrency = (val: number) =>
    `$${val.toLocaleString("en-US", { minimumFractionDigits: 0, maximumFractionDigits: 0 })}`;

  // Top-level KPIs
  const kpis = [
    { label: "Annual Risk Exposure", value: formatCurrency(data.annualRiskExposure), color: "#EF4444" },
    {
      label: "Mitigated Risk",
      value: formatCurrency(data.mitigatedRisk),
      trend: "down" as const,
      delta: "Reduced",
      color: "#22C55E",
    },
    { label: "Residual Risk", value: formatCurrency(data.residualRisk), color: "#F97316" },
    {
      label: "Security ROI",
      value: `${data.roiPercentage}%`,
      trend: "up" as const,
      delta: "Return on Investment",
      color: brandColor,
    },
  ];

  doc.y = drawKpiCards(doc, kpis, marginLeft, doc.y, contentWidth);
  doc.moveDown(0.5);

  // Estimated cost of breach
  doc.font("Helvetica-Bold").fontSize(9).fillColor(TEXT_PRIMARY);
  doc.text("Estimated Cost of Breach:", marginLeft, doc.y, { continued: true });
  doc.font("Helvetica-Bold").fontSize(9).fillColor("#DC2626");
  doc.text(` ${formatCurrency(data.costOfBreach)}`, { continued: false });
  doc.moveDown(0.5);

  // Risk breakdown table
  if (data.riskItems.length > 0) {
    doc.font("Helvetica-Bold").fontSize(9).fillColor(TEXT_PRIMARY);
    doc.text("Risk Breakdown by Category", marginLeft, doc.y);
    doc.moveDown(0.3);

    drawTable(
      doc,
      ["Category", "Exposure", "Probability", "Annualized Loss"],
      data.riskItems.map((item) => [
        item.category,
        formatCurrency(item.exposure),
        `${(item.probability * 100).toFixed(1)}%`,
        formatCurrency(item.annualizedLoss),
      ]),
      contentWidth,
      marginLeft,
    );
  }
}

// ─── Page Header ─────────────────────────────────────────────────────────────

function drawPageHeader(
  doc: PDFKit.PDFDocument,
  title: string,
  generatedAt: string,
  logoPath: string | null,
  brandColor: string,
  confidential: boolean,
  companyName: string,
): void {
  const pageWidth = doc.page.width;
  const marginLeft = doc.page.margins.left;
  const marginRight = doc.page.margins.right;
  const headerY = 15;

  doc.rect(0, 0, pageWidth, 3).fill(brandColor);
  doc.rect(0, 3, pageWidth, 48).fill(HEADER_BG);

  if (logoPath && fs.existsSync(logoPath)) {
    doc.image(logoPath, marginLeft, headerY, { height: 28 });
  }

  doc.font("Helvetica-Bold").fontSize(9).fillColor(TEXT_PRIMARY);
  doc.text(title, marginLeft + 80, headerY + 4, { width: 250 });
  doc.font("Helvetica").fontSize(7).fillColor(TEXT_SECONDARY);
  doc.text(formatDate(generatedAt), marginLeft + 80, headerY + 18);

  if (confidential) {
    const badgeX = pageWidth - marginRight - 85;
    doc.rect(badgeX, headerY + 2, 75, 18).fill("#FEF2F2");
    doc
      .rect(badgeX, headerY + 2, 75, 18)
      .strokeColor("#DC2626")
      .lineWidth(0.5)
      .stroke();
    doc.font("Helvetica-Bold").fontSize(7).fillColor("#DC2626");
    doc.text("CONFIDENTIAL", badgeX, headerY + 7, { width: 75, align: "center" });
  }

  doc
    .moveTo(marginLeft, 51)
    .lineTo(pageWidth - marginRight, 51)
    .strokeColor(brandColor)
    .lineWidth(1)
    .stroke();
}

// ─── Footer ──────────────────────────────────────────────────────────────────

function drawFooterLine(
  doc: PDFKit.PDFDocument,
  currentPage: number,
  totalPages: number,
  companyName: string,
  confidential: boolean,
  brandColor: string,
): void {
  const pageWidth = doc.page.width;
  const marginLeft = doc.page.margins.left;
  const marginRight = doc.page.margins.right;
  const footerY = doc.page.height - 50;
  const contentWidth = pageWidth - marginLeft - marginRight;

  doc
    .moveTo(marginLeft, footerY)
    .lineTo(pageWidth - marginRight, footerY)
    .strokeColor(BORDER_COLOR)
    .lineWidth(0.5)
    .stroke();

  doc.font("Helvetica").fontSize(7).fillColor(TEXT_SECONDARY);
  doc.text(companyName, marginLeft, footerY + 8, { width: contentWidth / 3 });

  const classification = confidential ? "CONFIDENTIAL" : "Internal Use Only";
  doc
    .font("Helvetica-Oblique")
    .fontSize(7)
    .fillColor(confidential ? "#DC2626" : TEXT_SECONDARY);
  doc.text(classification, marginLeft + contentWidth / 3, footerY + 8, { width: contentWidth / 3, align: "center" });

  doc.font("Helvetica").fontSize(7).fillColor(TEXT_SECONDARY);
  doc.text(`Page ${currentPage} of ${totalPages}`, marginLeft + (contentWidth * 2) / 3, footerY + 8, {
    width: contentWidth / 3,
    align: "right",
  });

  doc.rect(0, doc.page.height - 3, pageWidth, 3).fill(brandColor);
}

// ─── Watermark ───────────────────────────────────────────────────────────────

function drawWatermark(doc: PDFKit.PDFDocument): void {
  const pageWidth = doc.page.width;
  doc.save();
  doc.opacity(0.04);
  doc.font("Helvetica-Bold").fontSize(72).fillColor("#DC2626");
  doc.translate(pageWidth / 2, doc.page.height / 2);
  doc.rotate(-45, { origin: [0, 0] });
  doc.text("CONFIDENTIAL", -200, -30, { width: 400, align: "center" });
  doc.restore();
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function formatDate(isoStr: string): string {
  try {
    const d = new Date(isoStr);
    if (isNaN(d.getTime())) return isoStr;
    return d.toLocaleDateString("en-US", {
      year: "numeric",
      month: "long",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      timeZoneName: "short",
    });
  } catch {
    return isoStr;
  }
}
