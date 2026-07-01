import { redirect } from "@sveltejs/kit";
import { resolve } from "$app/paths";

// Demo-only: this sessionStorage value is a UI convenience, not an auth check.
// It is trivially forgeable in DevTools. The real session is the signed cookie
// issued by /api/login/complete; production code must gate access on that.
export function load() {
  const username = sessionStorage.getItem("username");
  if (!username) {
    redirect(307, resolve("/"));
  }

  return { username };
}
