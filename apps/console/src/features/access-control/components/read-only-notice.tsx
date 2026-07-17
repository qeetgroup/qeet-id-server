import { Alert, AlertDescription, AlertTitle } from "@qeetrix/ui";
import { EyeIcon } from "lucide-react";

export function ReadOnlyNotice({
  title = "Read-only access",
  description = "You can inspect and export this data, but your workspace role cannot change it.",
}: {
  title?: string;
  description?: string;
}) {
  return (
    <Alert>
      <EyeIcon />
      <AlertTitle>{title}</AlertTitle>
      <AlertDescription>{description}</AlertDescription>
    </Alert>
  );
}
