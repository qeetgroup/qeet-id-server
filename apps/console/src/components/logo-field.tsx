import { Button, Input, cn } from "@qeetrix/ui";
import { ImageIcon, Trash2Icon, UploadCloudIcon } from "lucide-react";
import { useRef, useState } from "react";

type LogoFieldProps = {
  /** Current logo source — a public URL or a data: URL. Empty = no logo. */
  value: string;
  /** Emits the new value: a data URL after a file pick, or the typed URL. */
  onChange: (next: string) => void;
  /** Max file size in MB before the pick is rejected. Defaults to 2. */
  maxSizeMB?: number;
  /** Accepted MIME types for the file input. Defaults to all images. */
  accept?: string;
  disabled?: boolean;
  hint?: string;
  className?: string;
};

/**
 * Console-local logo picker. Replaces `@qeetrix/ui`'s `LogoUploader`, whose
 * drop-zone doesn't open the file dialog on click (the hidden <input> has no
 * label association). Here the dropzone and the Replace button both call the
 * file input's `.click()` directly, so clicking always opens the picker.
 *
 * Both input paths share the one `value` slot — a file becomes a data URL via
 * FileReader; a pasted URL is emitted verbatim — so callers treat them the same.
 */
export function LogoField({
  value,
  onChange,
  maxSizeMB = 2,
  accept = "image/*",
  disabled,
  hint,
  className,
}: LogoFieldProps) {
  const [dragOver, setDragOver] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const maxBytes = maxSizeMB * 1024 * 1024;

  function handleFile(file: File) {
    setError(null);
    if (!file.type.startsWith("image/")) {
      setError("That doesn't look like an image file.");
      return;
    }
    if (file.size > maxBytes) {
      setError(`File is larger than ${maxSizeMB} MB.`);
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      if (typeof reader.result === "string") onChange(reader.result);
    };
    reader.onerror = () => setError("Couldn't read that file.");
    reader.readAsDataURL(file);
  }

  function openPicker() {
    if (!disabled) inputRef.current?.click();
  }

  function clearLogo() {
    onChange("");
    setError(null);
    if (inputRef.current) inputRef.current.value = "";
  }

  return (
    <div className={cn("flex flex-col gap-2", className)}>
      {value ? (
        <div className="flex items-start gap-3 rounded-lg border bg-muted/30 p-3">
          <div className="flex size-16 shrink-0 items-center justify-center overflow-hidden rounded-md border bg-background">
            <img
              src={value}
              alt="Logo preview"
              className="h-full w-full object-contain"
              onError={() => setError("Couldn't render that source as an image.")}
            />
          </div>
          <div className="flex flex-1 flex-col gap-1">
            <p className="text-sm font-medium">Logo set</p>
            <p className="line-clamp-1 text-xs text-muted-foreground">
              {value.startsWith("data:") ? "Uploaded file (preview)" : value}
            </p>
            <div className="mt-1 flex gap-2">
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={disabled}
                onClick={openPicker}
              >
                <UploadCloudIcon /> Replace
              </Button>
              <Button type="button" variant="ghost" size="sm" disabled={disabled} onClick={clearLogo}>
                <Trash2Icon /> Remove
              </Button>
            </div>
          </div>
        </div>
      ) : (
        <button
          type="button"
          disabled={disabled}
          onClick={openPicker}
          onDragOver={(e) => {
            e.preventDefault();
            if (!disabled) setDragOver(true);
          }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragOver(false);
            if (disabled) return;
            const file = e.dataTransfer.files[0];
            if (file) handleFile(file);
          }}
          className={cn(
            "flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed p-6 text-center transition-colors",
            dragOver ? "border-primary bg-primary/5" : "border-muted-foreground/30",
            disabled && "pointer-events-none opacity-50",
          )}
        >
          <ImageIcon className="size-6 text-muted-foreground" />
          <span className="text-sm font-medium">Drop a logo here or click to upload</span>
          <span className="text-xs text-muted-foreground">
            PNG, JPG, SVG, or WEBP up to {maxSizeMB} MB
          </span>
        </button>
      )}

      <input
        ref={inputRef}
        type="file"
        accept={accept}
        disabled={disabled}
        aria-label="Upload a logo file"
        className="sr-only"
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) handleFile(f);
        }}
      />

      {/* URL fallback so already-hosted logos work without re-uploading. */}
      <Input
        type="url"
        inputMode="url"
        placeholder="…or paste a logo URL"
        value={value && !value.startsWith("data:") ? value : ""}
        onChange={(e) => onChange(e.target.value)}
        disabled={disabled}
        aria-label="Logo URL"
      />

      {hint && !error && <p className="text-xs text-muted-foreground">{hint}</p>}
      {error && (
        <p role="alert" className="text-xs text-destructive">
          {error}
        </p>
      )}
    </div>
  );
}
