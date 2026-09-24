import { describe, expect, it } from "vitest";

import {
  CONVEY_OUT_OF_BAND,
  MINIMUM_PASSWORD_LENGTH,
  type Invitation,
  type User,
  describeSignIn,
  expiresIn,
  passwordProblem,
  whyNotDisable,
} from "./users";

function user(over: Partial<User> = {}): User {
  return {
    id: "018f0000-0000-7000-8000-00000000aaaa",
    email: "somebody@example.test",
    display_name: "Somebody",
    created_at: "2026-09-01T10:00:00Z",
    break_glass: false,
    has_password: true,
    sso_linked: false,
    ...over,
  };
}

describe("how somebody signs in", () => {
  it("distinguishes the three states the product actually has", () => {
    expect(describeSignIn(user())).toBe("password");
    expect(describeSignIn(user({ has_password: false, sso_linked: true }))).toBe(
      "single sign-on",
    );
    expect(describeSignIn(user({ has_password: true, sso_linked: true }))).toBe(
      "password or single sign-on",
    );
  });

  it("says so plainly when an account cannot sign in at all", () => {
    // Migration 0024's `app_user_can_authenticate_somehow` refuses this, so it is only
    // reachable if somebody has been in the database by hand. Worth naming rather than
    // rendering a blank cell.
    expect(describeSignIn(user({ has_password: false, sso_linked: false }))).toBe(
      "cannot sign in",
    );
  });
});

describe("suspending an account", () => {
  const me = "018f0000-0000-7000-8000-00000000aaaa";

  it("refuses your own account before the click, not after", () => {
    expect(whyNotDisable(user({ id: me }), me)).toMatch(/another administrator/);
  });

  it("allows anybody else", () => {
    expect(whyNotDisable(user({ id: "018f0000-0000-7000-8000-00000000bbbb" }), me)).toBeNull();
  });

  it("does not guess at the last-administrator rule", () => {
    // The server decides that under a lock across every tenant, and a screen that guessed
    // would hide a control somebody needs. So the only sole admin in the organization still
    // gets a button, and the 409 explains itself.
    const only = user({ id: "018f0000-0000-7000-8000-00000000cccc" });
    expect(whyNotDisable(only, me)).toBeNull();
  });

  it("says nothing about an account that is already suspended", () => {
    expect(whyNotDisable(user({ disabled_at: "2026-09-02T10:00:00Z" }), "other")).toBeNull();
  });
});

describe("password rules", () => {
  it("asks only for length", () => {
    expect(passwordProblem("x".repeat(MINIMUM_PASSWORD_LENGTH))).toBeNull();
    expect(passwordProblem("short")).toMatch(/at least/i);
  });

  it("counts characters rather than bytes", () => {
    // Twelve code points that are twenty-four bytes. A byte-length check would accept six
    // of them, which is the bug this asserts against.
    expect(passwordProblem("é".repeat(MINIMUM_PASSWORD_LENGTH))).toBeNull();
    expect(passwordProblem("é".repeat(MINIMUM_PASSWORD_LENGTH - 1))).toMatch(/at least/i);
  });

  it("does not demand a symbol, a digit or a capital", () => {
    expect(passwordProblem("all lower case words")).toBeNull();
  });

  it("checks the confirmation only when there is one", () => {
    const long = "a sufficiently long one";
    expect(passwordProblem(long)).toBeNull();
    expect(passwordProblem(long, long)).toBeNull();
    expect(passwordProblem(long, `${long}!`)).toBe("The two do not match");
  });

  it("reports length before mismatch, because that is the fixable one", () => {
    expect(passwordProblem("short", "different")).toMatch(/at least/i);
  });
});

describe("when an invitation stops working", () => {
  const now = new Date("2026-09-24T12:00:00Z");
  function invitation(expires: string): Invitation {
    return {
      id: "018f0000-0000-7000-8000-00000000dddd",
      email: "new@example.test",
      display_name: "New",
      invited_at: "2026-09-24T11:00:00Z",
      expires_at: expires,
    };
  }

  it("counts in hours while that is what somebody can act on", () => {
    expect(expiresIn(invitation("2026-09-24T15:00:00Z"), now)).toBe("expires in 3 hours");
    expect(expiresIn(invitation("2026-09-24T13:30:00Z"), now)).toBe("expires in 1 hour");
  });

  it("says within the hour rather than zero hours", () => {
    expect(expiresIn(invitation("2026-09-24T12:30:00Z"), now)).toBe("expires within the hour");
  });

  it("switches to days once hours stop being useful", () => {
    expect(expiresIn(invitation("2026-10-01T12:00:00Z"), now)).toBe("expires in 7 days");
  });

  it("says expired rather than a negative count", () => {
    expect(expiresIn(invitation("2026-09-23T12:00:00Z"), now)).toBe("expired");
  });

  it("does not render NaN for a timestamp it cannot read", () => {
    expect(expiresIn(invitation("not a date"), now)).toBe("unknown");
  });
});

describe("the link somebody has to convey themselves", () => {
  it("says it is shown once and what to do if it is lost", () => {
    // The product has no organization-level mail transport and an air-gapped installation
    // may never have one, so this sentence is the delivery mechanism.
    expect(CONVEY_OUT_OF_BAND).toMatch(/shown once/);
    expect(CONVEY_OUT_OF_BAND).toMatch(/invite them again/);
  });
});
