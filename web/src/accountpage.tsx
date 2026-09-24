/**
 * Your own account — `docs/user-administration.md` §4.6.
 *
 * Changing a password is not administration: every user needs it and no role is required, so
 * it is here rather than on the People screen. Until this existed, nobody could change their
 * own password at all — `update_password_hash` was reached only by the transparent rehash
 * that happens during a successful sign-in.
 *
 * # Why it asks for the current one
 *
 * A session cookie is not evidence of knowing the secret being replaced. Somebody who picked
 * up an unlocked laptop should not be able to lock its owner out of their own installation.
 *
 * # Why the other sessions end
 *
 * Somebody changing a password usually believes the old one leaked, and leaving the other
 * sessions alive would defeat the act. The session doing the typing survives, because being
 * signed out of the tab you are working in reads as a bug rather than as a precaution.
 */

import { useMutation } from "@tanstack/react-query";
import { useState } from "react";

import { message } from "./query";
import { useShell } from "./shell";
import { MINIMUM_PASSWORD_LENGTH, changePassword, passwordProblem } from "./users";

export function AccountPage() {
  const { me } = useShell();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [changed, setChanged] = useState(false);

  const submit = useMutation({
    mutationFn: () => changePassword(current, next),
    onSuccess: () => {
      setChanged(true);
      setCurrent("");
      setNext("");
      setConfirm("");
    },
  });

  const problem = next ? passwordProblem(next, confirm) : null;

  return (
    <>
      <h1>Your account</h1>
      <p className="dim">
        {me.display_name} — <span className="mono">{me.email}</span>
      </p>

      <h2>Change your password</h2>

      {changed && (
        <div className="notice" role="status">
          Changed. Any other session you had signed in elsewhere has been ended; this one is
          still working.
        </div>
      )}

      <form
        className="inline-form"
        onSubmit={(e) => {
          e.preventDefault();
          if (!problem) submit.mutate();
        }}
      >
        <label>
          Your current password
          <input
            type="password"
            autoComplete="current-password"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
            required
          />
        </label>
        <label>
          New password
          <input
            type="password"
            autoComplete="new-password"
            value={next}
            onChange={(e) => setNext(e.target.value)}
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
          At least {MINIMUM_PASSWORD_LENGTH} characters, and that is the whole rule.
        </p>

        {problem && (
          <div className="problem" role="alert">
            {problem}
          </div>
        )}

        <button
          type="submit"
          disabled={submit.isPending || Boolean(problem) || !current || !confirm}
        >
          {submit.isPending ? "Changing…" : "Change it"}
        </button>

        {submit.isError && (
          <div className="problem" role="alert">
            {message(submit.error)}
          </div>
        )}
      </form>
    </>
  );
}
