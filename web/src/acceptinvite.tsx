/**
 * Accepting an invitation — `docs/user-administration.md` §4.1.
 *
 * The only page in this app that works with no session, other than signing in. Whoever
 * follows the link has no account yet: the token is the whole authorisation, and this is
 * where they choose the password nobody else will ever know.
 *
 * # Every refusal is the same sentence
 *
 * The server answers one message for a token that is wrong, spent, withdrawn or expired,
 * because telling somebody *which* would confirm that a token had once been real. This page
 * shows what it was told and does not elaborate.
 *
 * # No session comes out of it
 *
 * Accepting creates the account and ends. Signing in is a separate act with its own audit
 * entry and its own cookies, and a page that did both would be a second login path to keep
 * correct. So this sends them to the sign-in form, which is where they were going anyway.
 */

import { useMutation } from "@tanstack/react-query";
import { useState } from "react";

import { message } from "./query";
import { MINIMUM_PASSWORD_LENGTH, accept, passwordProblem } from "./users";

export function AcceptInvitePage({ token }: { token: string }) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [done, setDone] = useState(false);

  const submit = useMutation({
    mutationFn: () => accept(token, password),
    onSuccess: () => setDone(true),
  });

  // Checked here as well as on the server, and the server is the one that counts. This
  // exists so somebody is told before they submit, not to decide anything.
  const problem = password ? passwordProblem(password, confirm) : null;

  if (done) {
    return (
      <main className="centred">
        <h1>You are in</h1>
        <p>
          Your account exists and your password is set. Nobody else knows it — not the person
          who invited you.
        </p>
        <p>
          <a href="/login">Sign in</a>
        </p>
      </main>
    );
  }

  return (
    <main className="centred">
      <h1>Choose a password</h1>
      <p className="dim">
        Somebody invited you to this installation. Setting a password here creates your
        account.
      </p>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (!problem) submit.mutate();
        }}
      >
        <label>
          Password
          <input
            type="password"
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            minLength={MINIMUM_PASSWORD_LENGTH}
          />
        </label>
        <label>
          Again
          <input
            type="password"
            autoComplete="new-password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            required
          />
        </label>

        <p className="dim">
          At least {MINIMUM_PASSWORD_LENGTH} characters. Length is the whole rule — nothing
          here asks for a symbol, because those mostly produce predictable substitutions.
        </p>

        {problem && (
          <div className="problem" role="alert">
            {problem}
          </div>
        )}

        <button type="submit" disabled={submit.isPending || Boolean(problem) || !confirm}>
          {submit.isPending ? "Setting…" : "Set my password"}
        </button>

        {submit.isError && (
          <div className="problem" role="alert">
            {message(submit.error)}
          </div>
        )}
      </form>
    </main>
  );
}
