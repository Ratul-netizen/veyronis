/**
 * Signing in.
 *
 * Everything else that was here has grown its own file — the inventory in resources.tsx,
 * the explorer in explore.tsx, the overview in overview.tsx. This is the one page that
 * exists outside the shell, because it is the one a person reaches without a session.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { useState } from "react";

import { ApiError, api } from "./api";

export function LoginPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  // Asked on load rather than behind a toggle: an organization that has switched SSO on
  // wants its people to see the button first, and a deployment with none configured gets
  // an empty list and the form it already had.
  //
  // A failure here is not an error on this page. The password form still works, and a
  // sign-in screen that shows a red banner because an unrelated endpoint was slow is a
  // support call.
  const methods = useQuery({
    queryKey: ["auth", "methods"],
    queryFn: () => api.signInMethods(),
    retry: false,
  });
  const providers = methods.data?.providers ?? [];

  const login = useMutation({
    mutationFn: () => api.login(email, password),
    onSuccess: async () => {
      // The session cookie has changed, so anything cached under the old one is about
      // somebody else. Clearing beats invalidating: this is a different user.
      queryClient.clear();
      await navigate({ to: "/" });
    },
  });

  return (
    <div className="login">
      <h1>uops</h1>
      <p className="dim">Sign in to continue.</p>

      {providers.length > 0 && (
        <div className="sso">
          {providers.map((provider) => (
            // A link, not a button with an onClick. The flow is a redirect to the
            // identity provider and back, so the browser has to navigate — a fetch
            // would follow the redirect itself and land the provider's sign-in page
            // inside a response body nobody can see.
            <a
              key={provider.id}
              className="primary"
              href={`${provider.start}?return_to=${encodeURIComponent("/")}`}
            >
              Sign in with {provider.name}
            </a>
          ))}
          <p className="dim or">or sign in with a password</p>
        </div>
      )}

      <form
        onSubmit={(e) => {
          e.preventDefault();
          login.mutate();
        }}
      >
        <label>
          Email
          <input
            type="email"
            autoComplete="username"
            autoFocus
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
        </label>

        <label>
          Password
          <input
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </label>

        {login.isError && (
          <div className="problem" role="alert">
            {/* Never "no such user" or "wrong password" — the server does not
                distinguish them and neither does this. An account-enumeration oracle
                in the error text would undo the constant-time login path behind it. */}
            {login.error instanceof ApiError && login.error.status === 401
              ? "Those credentials were not accepted."
              : "Sign-in failed. The server may be unreachable."}
          </div>
        )}

        <button type="submit" className="primary" disabled={login.isPending}>
          {login.isPending ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
