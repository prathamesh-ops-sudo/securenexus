import PDFDocument from "pdfkit";
import path from "path";
import fs from "fs";

interface ReportSection {
  title: string;
  type: "table" | "summary" | "chart_data";
  columns?: string[];
  rows?: any[][];
  data?: Record<string, any>;
}

interface ReportData {
  title: string;
  generatedAt: string;
  reportType: string;
  orgId: string | null;
  sections: ReportSection[];
}

interface PdfOptions {
  confidential?: boolean;
  orgName?: string;
  generatedBy?: string;
}

/** Report types that should be marked CONFIDENTIAL in PDF output */
export const CONFIDENTIAL_REPORT_TYPES = ["executive_summary", "compliance", "incidents"];

// ATS brand color
const ATS_BLUE = "#0040FF";
const HEADER_BG = "#F0F4FF";
const TABLE_HEADER_BG = "#1a1a2e";
const TABLE_HEADER_TEXT = "#FFFFFF";
const TABLE_ALT_ROW = "#F8F9FC";
const TEXT_PRIMARY = "#1a1a2e";
const TEXT_SECONDARY = "#64748b";
const BORDER_COLOR = "#E2E8F0";

function getLogoPath(): string | null {
  // Try multiple paths for the logo
  const candidates = [
    path.join(process.cwd(), "client", "public", "ats-logo.png"),
    path.join(process.cwd(), "dist", "public", "ats-logo.png"),
    path.join(__dirname, "..", "client", "public", "ats-logo.png"),
  ];
  for (const p of candidates) {
    if (fs.existsSync(p)) return p;
  }
  return null;
}

export function generatePdfReport(data: ReportData, options: PdfOptions = {}): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({
        size: "A4",
        margins: { top: 80, bottom: 80, left: 50, right: 50 },
        bufferPages: true,
        info: {
          Title: data.title,
          Author: "Arica Tech Solutions — SecureNexus Platform",
          Subject: `${data.reportType} Report`,
          Creator: "SecureNexus Report Engine",
          Producer: "ATS SecureNexus",
        },
      });

      const chunks: Buffer[] = [];
      doc.on("data", (chunk: Buffer) => chunks.push(chunk));
      doc.on("end", () => resolve(Buffer.concat(chunks)));
      doc.on("error", reject);

      const pageWidth = doc.page.width;
      const contentWidth = pageWidth - doc.page.margins.left - doc.page.margins.right;
      const logoPath = getLogoPath();

      // Register fonts (use built-in Helvetica)
      const FONT_REGULAR = "Helvetica";
      const FONT_BOLD = "Helvetica-Bold";
      const FONT_OBLIQUE = "Helvetica-Oblique";

      // ========================================
      // COVER PAGE
      // ========================================
      drawCoverPage(doc, data, options, logoPath, pageWidth, contentWidth, FONT_REGULAR, FONT_BOLD, FONT_OBLIQUE);

      // ========================================
      // CONTENT PAGES
      // ========================================
      doc.addPage();

      for (let i = 0; i < data.sections.length; i++) {
        const section = data.sections[i];

        // Check if we need a new page (leave room for section header + some content)
        if (doc.y > doc.page.height - 160) {
          doc.addPage();
        }

        drawSection(doc, section, i, contentWidth, FONT_REGULAR, FONT_BOLD);
      }

      // ========================================
      // ADD HEADERS AND FOOTERS TO ALL PAGES
      // ========================================
      const totalPages = doc.bufferedPageRange().count;
      for (let i = 0; i < totalPages; i++) {
        doc.switchToPage(i);

        if (i === 0) {
          // Cover page — no header, but add footer
          drawFooter(doc, i + 1, totalPages, data, options, pageWidth, FONT_REGULAR, FONT_OBLIQUE);
          continue;
        }

        // Header
        drawHeader(doc, data, options, logoPath, pageWidth, FONT_REGULAR, FONT_BOLD);

        // Footer
        drawFooter(doc, i + 1, totalPages, data, options, pageWidth, FONT_REGULAR, FONT_OBLIQUE);

        // Confidential watermark
        if (options.confidential) {
          drawConfidentialWatermark(doc, pageWidth);
        }
      }

      doc.end();
    } catch (err) {
      reject(err);
    }
  });
}

function drawCoverPage(
  doc: PDFKit.PDFDocument,
  data: ReportData,
  options: PdfOptions,
  logoPath: string | null,
  pageWidth: number,
  contentWidth: number,
  fontRegular: string,
  fontBold: string,
  fontOblique: string,
): void {
  const centerX = pageWidth / 2;

  // Top bar
  doc.rect(0, 0, pageWidth, 6).fill(ATS_BLUE);

  // Logo
  if (logoPath) {
    doc.image(logoPath, centerX - 60, 100, { width: 120 });
  }

  // Company name
  doc.font(fontBold).fontSize(14).fillColor(ATS_BLUE);
  doc.text("ARICA TECH SOLUTIONS", 0, 240, { align: "center", width: pageWidth });

  doc.font(fontRegular).fontSize(9).fillColor(TEXT_SECONDARY);
  doc.text("Enterprise Security Platform", 0, 258, { align: "center", width: pageWidth });

  // Divider line
  doc
    .moveTo(centerX - 100, 290)
    .lineTo(centerX + 100, 290)
    .strokeColor(ATS_BLUE)
    .lineWidth(1.5)
    .stroke();

  // Report title
  doc.font(fontBold).fontSize(24).fillColor(TEXT_PRIMARY);
  doc.text(data.title, 0, 320, { align: "center", width: pageWidth });

  // Subtitle based on report type
  const subtitleMap: Record<string, string> = {
    soc_kpi: "Security Operations Center Performance Metrics",
    incidents: "Incident Management Summary & Analysis",
    attack_coverage: "MITRE ATT&CK Framework Detection Coverage",
    connector_health: "Data Source Integration Health Status",
    executive_summary: "Executive Security Posture Briefing",
    compliance: "Regulatory Compliance & Data Governance Status",
  };
  const subtitle = subtitleMap[data.reportType] || "";
  if (subtitle) {
    doc.font(fontRegular).fontSize(11).fillColor(TEXT_SECONDARY);
    doc.text(subtitle, 0, 355, { align: "center", width: pageWidth });
  }

  // Confidential banner
  if (options.confidential) {
    doc.rect(centerX - 80, 400, 160, 28).fill("#FEF2F2");
    doc
      .rect(centerX - 80, 400, 160, 28)
      .strokeColor("#DC2626")
      .lineWidth(1)
      .stroke();
    doc.font(fontBold).fontSize(10).fillColor("#DC2626");
    doc.text("CONFIDENTIAL", 0, 407, { align: "center", width: pageWidth });
  }

  // Metadata table
  const metaY = options.confidential ? 460 : 420;
  const metaX = doc.page.margins.left + 60;
  const metaLabelWidth = 120;

  const metaRows: [string, string][] = [
    ["Report Date", formatDate(data.generatedAt)],
    ["Report Type", data.reportType.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())],
  ];
  if (options.orgName) metaRows.push(["Organization", options.orgName]);
  if (options.generatedBy) metaRows.push(["Generated By", options.generatedBy]);
  metaRows.push(["Classification", options.confidential ? "Confidential" : "Internal Use Only"]);

  for (let i = 0; i < metaRows.length; i++) {
    const y = metaY + i * 22;
    doc.font(fontBold).fontSize(9).fillColor(TEXT_SECONDARY);
    doc.text(metaRows[i][0] + ":", metaX, y, { width: metaLabelWidth });
    doc.font(fontRegular).fontSize(9).fillColor(TEXT_PRIMARY);
    doc.text(metaRows[i][1], metaX + metaLabelWidth, y, { width: contentWidth - metaLabelWidth - 60 });
  }

  // Bottom divider
  doc
    .moveTo(doc.page.margins.left, doc.page.height - 120)
    .lineTo(pageWidth - doc.page.margins.right, doc.page.height - 120)
    .strokeColor(BORDER_COLOR)
    .lineWidth(0.5)
    .stroke();

  // Disclaimer
  doc.font(fontOblique).fontSize(7).fillColor(TEXT_SECONDARY);
  doc.text(
    "This report was automatically generated by ATS SecureNexus. The information contained herein is intended " +
      "for the designated recipients only. Unauthorized disclosure, copying, or distribution is strictly prohibited.",
    doc.page.margins.left,
    doc.page.height - 110,
    { align: "center", width: contentWidth },
  );

  // Bottom bar
  doc.rect(0, doc.page.height - 6, pageWidth, 6).fill(ATS_BLUE);
}

function drawHeader(
  doc: PDFKit.PDFDocument,
  data: ReportData,
  options: PdfOptions,
  logoPath: string | null,
  pageWidth: number,
  fontRegular: string,
  fontBold: string,
): void {
  const marginLeft = doc.page.margins.left;
  const marginRight = doc.page.margins.right;
  const headerY = 15;

  // Top accent bar
  doc.rect(0, 0, pageWidth, 3).fill(ATS_BLUE);

  // Header background
  doc.rect(0, 3, pageWidth, 48).fill(HEADER_BG);

  // Logo in header
  if (logoPath) {
    doc.image(logoPath, marginLeft, headerY, { height: 28 });
  }

  // Report title in header
  doc.font(fontBold).fontSize(9).fillColor(TEXT_PRIMARY);
  doc.text(data.title, marginLeft + 80, headerY + 4, { width: 250 });
  doc.font(fontRegular).fontSize(7).fillColor(TEXT_SECONDARY);
  doc.text(formatDate(data.generatedAt), marginLeft + 80, headerY + 18);

  // Confidential badge in header
  if (options.confidential) {
    const badgeX = pageWidth - marginRight - 85;
    doc.rect(badgeX, headerY + 2, 75, 18).fill("#FEF2F2");
    doc
      .rect(badgeX, headerY + 2, 75, 18)
      .strokeColor("#DC2626")
      .lineWidth(0.5)
      .stroke();
    doc.font(fontBold).fontSize(7).fillColor("#DC2626");
    doc.text("CONFIDENTIAL", badgeX, headerY + 7, { width: 75, align: "center" });
  }

  // Header divider
  doc
    .moveTo(marginLeft, 51)
    .lineTo(pageWidth - marginRight, 51)
    .strokeColor(ATS_BLUE)
    .lineWidth(1)
    .stroke();
}

function drawFooter(
  doc: PDFKit.PDFDocument,
  currentPage: number,
  totalPages: number,
  data: ReportData,
  options: PdfOptions,
  pageWidth: number,
  fontRegular: string,
  fontOblique: string,
): void {
  const marginLeft = doc.page.margins.left;
  const marginRight = doc.page.margins.right;
  const footerY = doc.page.height - 50;
  const contentWidth = pageWidth - marginLeft - marginRight;

  // Footer divider
  doc
    .moveTo(marginLeft, footerY)
    .lineTo(pageWidth - marginRight, footerY)
    .strokeColor(BORDER_COLOR)
    .lineWidth(0.5)
    .stroke();

  // Left: company
  doc.font(fontRegular).fontSize(7).fillColor(TEXT_SECONDARY);
  doc.text("Arica Tech Solutions Pvt. Ltd.", marginLeft, footerY + 8, { width: contentWidth / 3 });

  // Center: classification
  const classification = options.confidential ? "CONFIDENTIAL" : "Internal Use Only";
  doc
    .font(fontOblique)
    .fontSize(7)
    .fillColor(options.confidential ? "#DC2626" : TEXT_SECONDARY);
  doc.text(classification, marginLeft + contentWidth / 3, footerY + 8, {
    width: contentWidth / 3,
    align: "center",
  });

  // Right: page number
  doc.font(fontRegular).fontSize(7).fillColor(TEXT_SECONDARY);
  doc.text(`Page ${currentPage} of ${totalPages}`, marginLeft + (contentWidth * 2) / 3, footerY + 8, {
    width: contentWidth / 3,
    align: "right",
  });

  // Bottom accent bar
  doc.rect(0, doc.page.height - 3, pageWidth, 3).fill(ATS_BLUE);
}

function drawConfidentialWatermark(doc: PDFKit.PDFDocument, pageWidth: number): void {
  doc.save();
  doc.opacity(0.04);
  doc.font("Helvetica-Bold").fontSize(72).fillColor("#DC2626");
  doc.translate(pageWidth / 2, doc.page.height / 2);
  doc.rotate(-45, { origin: [0, 0] });
  doc.text("CONFIDENTIAL", -200, -30, { width: 400, align: "center" });
  doc.restore();
}

function drawSection(
  doc: PDFKit.PDFDocument,
  section: ReportSection,
  index: number,
  contentWidth: number,
  fontRegular: string,
  fontBold: string,
): void {
  const marginLeft = doc.page.margins.left;

  // Section number and title
  doc.rect(marginLeft, doc.y, 4, 18).fill(ATS_BLUE);

  doc.font(fontBold).fontSize(13).fillColor(TEXT_PRIMARY);
  doc.text(`${index + 1}. ${section.title}`, marginLeft + 12, doc.y - 16, { width: contentWidth - 12 });
  doc.moveDown(0.5);

  if (section.type === "summary" && section.data) {
    drawSummarySection(doc, section.data, contentWidth, marginLeft, fontRegular, fontBold);
  } else if (section.type === "table" && section.columns && section.rows) {
    drawTableSection(doc, section.columns, section.rows, contentWidth, marginLeft, fontRegular, fontBold);
  }

  doc.moveDown(1.2);
}

function drawSummarySection(
  doc: PDFKit.PDFDocument,
  data: Record<string, any>,
  contentWidth: number,
  marginLeft: number,
  fontRegular: string,
  fontBold: string,
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

    // Check page break
    if (y + cardHeight > doc.page.height - 100) {
      doc.addPage();
      doc.y = doc.page.margins.top + 60;
      // Recalculate - restart this section on new page
    }

    // Card background
    doc.roundedRect(x, y, cardWidth, cardHeight, 4).fill("#F8FAFC");
    doc.roundedRect(x, y, cardWidth, cardHeight, 4).strokeColor(BORDER_COLOR).lineWidth(0.5).stroke();

    // Left accent
    doc.rect(x, y + 4, 3, cardHeight - 8).fill(ATS_BLUE);

    // Label
    doc.font(fontRegular).fontSize(7.5).fillColor(TEXT_SECONDARY);
    doc.text(entries[i][0], x + 12, y + 10, { width: cardWidth - 20 });

    // Value
    const val = entries[i][1];
    const valStr = val === null || val === undefined ? "—" : String(val);
    doc.font(fontBold).fontSize(16).fillColor(TEXT_PRIMARY);
    doc.text(valStr, x + 12, y + 26, { width: cardWidth - 20 });
  }

  const totalRows = Math.ceil(entries.length / colCount);
  doc.y = doc.y + totalRows * (cardHeight + 8) + 4;
}

function drawTableSection(
  doc: PDFKit.PDFDocument,
  columns: string[],
  rows: any[][],
  contentWidth: number,
  marginLeft: number,
  fontRegular: string,
  fontBold: string,
): void {
  if (columns.length === 0) return;

  const colWidths = calculateColumnWidths(columns, rows, contentWidth);
  const rowHeight = 22;
  const headerHeight = 26;
  const fontSize = 7.5;
  const headerFontSize = 8;

  // Table header
  let y = doc.y;
  doc.rect(marginLeft, y, contentWidth, headerHeight).fill(TABLE_HEADER_BG);

  let x = marginLeft;
  for (let c = 0; c < columns.length; c++) {
    doc.font(fontBold).fontSize(headerFontSize).fillColor(TABLE_HEADER_TEXT);
    doc.text(columns[c], x + 6, y + 7, { width: colWidths[c] - 12, lineBreak: false });
    x += colWidths[c];
  }
  y += headerHeight;

  // Table rows
  for (let r = 0; r < rows.length; r++) {
    // Page break check
    if (y + rowHeight > doc.page.height - 100) {
      doc.addPage();
      y = doc.page.margins.top + 60;

      // Re-draw header on new page
      doc.rect(marginLeft, y, contentWidth, headerHeight).fill(TABLE_HEADER_BG);
      x = marginLeft;
      for (let c = 0; c < columns.length; c++) {
        doc.font(fontBold).fontSize(headerFontSize).fillColor(TABLE_HEADER_TEXT);
        doc.text(columns[c], x + 6, y + 7, { width: colWidths[c] - 12, lineBreak: false });
        x += colWidths[c];
      }
      y += headerHeight;
    }

    // Alternating row background
    if (r % 2 === 0) {
      doc.rect(marginLeft, y, contentWidth, rowHeight).fill(TABLE_ALT_ROW);
    }

    // Row border
    doc
      .moveTo(marginLeft, y + rowHeight)
      .lineTo(marginLeft + contentWidth, y + rowHeight)
      .strokeColor(BORDER_COLOR)
      .lineWidth(0.3)
      .stroke();

    x = marginLeft;
    for (let c = 0; c < columns.length; c++) {
      const cellVal = rows[r]?.[c];
      const cellStr = cellVal === null || cellVal === undefined ? "" : String(cellVal);
      doc.font(fontRegular).fontSize(fontSize).fillColor(TEXT_PRIMARY);
      doc.text(cellStr, x + 6, y + 6, { width: colWidths[c] - 12, lineBreak: false, ellipsis: true });
      x += colWidths[c];
    }
    y += rowHeight;
  }

  // Table bottom border
  doc
    .moveTo(marginLeft, y)
    .lineTo(marginLeft + contentWidth, y)
    .strokeColor(TABLE_HEADER_BG)
    .lineWidth(1)
    .stroke();

  doc.y = y + 4;
}

function calculateColumnWidths(columns: string[], rows: any[][], totalWidth: number): number[] {
  // Simple proportional widths based on header length and content
  const minWidth = 50;
  const weights = columns.map((col, i) => {
    let maxLen = col.length;
    for (const row of rows.slice(0, 10)) {
      const val = row?.[i];
      if (val !== null && val !== undefined) {
        maxLen = Math.max(maxLen, String(val).length);
      }
    }
    return Math.max(maxLen, 4);
  });

  const totalWeight = weights.reduce((a, b) => a + b, 0);
  const widths = weights.map((w) => Math.max(minWidth, (w / totalWeight) * totalWidth));

  // Normalize to fill exact width
  const currentTotal = widths.reduce((a, b) => a + b, 0);
  const scale = totalWidth / currentTotal;
  return widths.map((w) => w * scale);
}

function formatDate(isoString: string): string {
  try {
    const d = new Date(isoString);
    return d.toLocaleDateString("en-IN", {
      year: "numeric",
      month: "long",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      timeZone: "Asia/Kolkata",
    });
  } catch {
    return isoString;
  }
}
