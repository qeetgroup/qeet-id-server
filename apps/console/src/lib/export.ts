// Shared client-side export helpers used by every list page's toolbar.
// Generalised from the original audit-logs implementation so a single,
// well-tested CSV escaper backs every "Download as CSV/JSON" action.

export type CsvColumn<T> = {
  header: string;
  value: (row: T) => unknown;
};

function csvCell(v: unknown): string {
  if (v == null) return "";
  const s = typeof v === "string" ? v : JSON.stringify(v);
  if (s.includes(",") || s.includes('"') || s.includes("\n") || s.includes("\r")) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

export function rowsToCsv<T>(rows: T[], columns: CsvColumn<T>[]): string {
  const lines = [columns.map((c) => csvCell(c.header)).join(",")];
  for (const row of rows) {
    lines.push(columns.map((c) => csvCell(c.value(row))).join(","));
  }
  return lines.join("\n");
}

export function downloadBlob(content: string, mime: string, filename: string): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function stamp(): string {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

export function exportToCsv<T>(name: string, rows: T[], columns: CsvColumn<T>[]): void {
  downloadBlob(rowsToCsv(rows, columns), "text/csv;charset=utf-8", `${name}-${stamp()}.csv`);
}

export function exportToJson<T>(name: string, rows: T[]): void {
  downloadBlob(JSON.stringify(rows, null, 2), "application/json", `${name}-${stamp()}.json`);
}
