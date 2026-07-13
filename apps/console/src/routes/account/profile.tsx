import {
  Avatar,
  AvatarFallback,
  AvatarImage,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Field,
  FieldDescription,
  FieldGroup,
  FieldLabel,
  Input,
  Skeleton,
} from "@qeetrix/ui";
import { useMutation } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { Loader2Icon, UploadIcon } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { api } from "@/lib/api";
import { useMe } from "@/lib/auth";

export const Route = createFileRoute("/account/profile")({ component: ProfilePage });

const AVATAR_PX = 192; // displayed at ≤64px; 192 keeps it crisp on retina
const MAX_FILE_BYTES = 8 * 1024 * 1024;

function initials(name: string) {
  return (
    name
      .split(/[\s@.]+/)
      .map((p) => p[0])
      .filter(Boolean)
      .slice(0, 2)
      .join("")
      .toUpperCase() || "?"
  );
}

// Resize + center-crop to a square JPEG data-URL. Keeps the payload tiny
// (~15–30 KB) so it fits the inline avatar_url column without object storage.
async function fileToAvatarDataUrl(file: File, size = AVATAR_PX): Promise<string> {
  const bitmap = await createImageBitmap(file);
  try {
    const canvas = document.createElement("canvas");
    canvas.width = size;
    canvas.height = size;
    const ctx = canvas.getContext("2d");
    if (!ctx) throw new Error("Canvas not supported");
    const scale = Math.max(size / bitmap.width, size / bitmap.height);
    const dw = bitmap.width * scale;
    const dh = bitmap.height * scale;
    ctx.drawImage(bitmap, (size - dw) / 2, (size - dh) / 2, dw, dh);
    return canvas.toDataURL("image/jpeg", 0.85);
  } finally {
    bitmap.close();
  }
}

function ProfilePage() {
  const { t } = useTranslation("account");
  const me = useMe();
  const fileRef = useRef<HTMLInputElement>(null);
  const [draft, setDraft] = useState({ display_name: "" });
  // undefined = unchanged · string = newly picked · "" = removed
  const [avatar, setAvatar] = useState<string | undefined>(undefined);
  const [uploadError, setUploadError] = useState<string | null>(null);

  // Hydrate the form once `me` resolves, then leave it alone so the
  // user's edits aren't blown away by background refetches.
  const hydratedRef = useState<{ done: boolean }>({ done: false })[0];
  useEffect(() => {
    if (!hydratedRef.done && me.data) {
      setDraft({ display_name: me.data.display_name ?? "" });
      hydratedRef.done = true;
    }
  }, [me.data, hydratedRef]);

  const saveM = useMutation({
    mutationFn: (body: { display_name?: string; avatar_url?: string }) =>
      api<unknown>(`/v1/users/${me.data?.id}`, { method: "PATCH", body }),
    onSuccess: () => {
      setAvatar(undefined); // fall back to the freshly-fetched server value
      void me.refetch();
    },
    meta: { successMessage: t("profile.toast.updated") },
  });

  const name = me.data?.display_name || me.data?.email?.split("@")[0] || "—";
  // What to show now: a pending pick wins; "" means removed → fallback.
  const shownAvatar = avatar !== undefined ? avatar || undefined : me.data?.avatar_url ?? undefined;

  async function onPickFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = ""; // let the same file be re-picked later
    if (!file) return;
    setUploadError(null);
    if (!file.type.startsWith("image/")) {
      setUploadError(t("profile.picture.errorNotImage"));
      return;
    }
    if (file.size > MAX_FILE_BYTES) {
      setUploadError(t("profile.picture.errorTooLarge"));
      return;
    }
    try {
      setAvatar(await fileToAvatarDataUrl(file));
    } catch {
      setUploadError(t("profile.picture.errorProcess"));
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("profile.title")}</CardTitle>
          <CardDescription>{t("profile.description")}</CardDescription>
        </CardHeader>
        <CardContent>
          {me.isLoading ? (
            <div className="space-y-3">
              <Skeleton className="h-16 w-16 rounded-full" />
              <Skeleton className="h-8 w-1/2" />
              <Skeleton className="h-8 w-1/2" />
            </div>
          ) : (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                saveM.mutate({
                  display_name: draft.display_name.trim() || undefined,
                  ...(avatar !== undefined ? { avatar_url: avatar } : {}),
                });
              }}
            >
              <FieldGroup>
                {/* Avatar */}
                <Field>
                  <FieldLabel>{t("profile.picture.label")}</FieldLabel>
                  <div className="flex items-center gap-4">
                    <Avatar className="size-16">
                      <AvatarImage src={shownAvatar} alt={name} />
                      <AvatarFallback className="text-lg">{initials(name)}</AvatarFallback>
                    </Avatar>
                    <div className="flex flex-col gap-2">
                      <div className="flex flex-wrap gap-2">
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          onClick={() => fileRef.current?.click()}
                        >
                          <UploadIcon /> {t("profile.picture.upload")}
                        </Button>
                        {shownAvatar && (
                          <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              setUploadError(null);
                              setAvatar("");
                            }}
                          >
                            {t("profile.picture.remove")}
                          </Button>
                        )}
                      </div>
                      <FieldDescription>{t("profile.picture.help")}</FieldDescription>
                      {uploadError && <p className="text-xs text-destructive">{uploadError}</p>}
                    </div>
                  </div>
                  <input
                    ref={fileRef}
                    type="file"
                    accept="image/*"
                    className="hidden"
                    onChange={onPickFile}
                  />
                </Field>

                <Field>
                  <FieldLabel htmlFor="display_name">{t("profile.displayName")}</FieldLabel>
                  <Input
                    id="display_name"
                    value={draft.display_name}
                    onChange={(e) => setDraft((d) => ({ ...d, display_name: e.target.value }))}
                    placeholder={t("profile.displayNamePlaceholder")}
                  />
                </Field>

                <Field>
                  <FieldLabel htmlFor="email">{t("profile.email")}</FieldLabel>
                  <Input id="email" value={me.data?.email ?? ""} disabled />
                  <FieldDescription>{t("profile.emailHelp")}</FieldDescription>
                </Field>

                <Field>
                  <Button type="submit" disabled={saveM.isPending}>
                    {saveM.isPending && <Loader2Icon className="animate-spin" />}
                    {saveM.isPending ? t("profile.saving") : t("profile.save")}
                  </Button>
                </Field>
              </FieldGroup>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
