import { redirect } from "next/navigation";

// The app has no index of its own; everything starts at /login (driven by the
// OAuth authorize redirect). Send stray visitors there.
export default function Home() {
  redirect("/login");
}
