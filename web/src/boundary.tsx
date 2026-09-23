/**
 * A boundary so that one optional view cannot take a screen with it.
 *
 * # Why this exists
 *
 * The 3D topology view is lazy-loaded behind a `Suspense`, and `Suspense` does not catch
 * errors — it catches *promises*. A throw inside the lazy component propagates past it to
 * whatever is above, which in this app was the router's own error page. So a single
 * `ReferenceError` in the WebGL layer replaced the entire Topology screen with
 * "Something went wrong", including the 2D view that was working perfectly.
 *
 * That is the wrong trade for an **optional** view. `docs/UI-3D-DEVICE-EXPLORER.md` is
 * explicit that 3D is an alternative way to look at the same graph, not the graph — so
 * when it fails the answer is to show the one that works and say why, not to lose both.
 *
 * # Why a class
 *
 * React has no hook for this. `getDerivedStateFromError` is only available on a class, and
 * a dependency that provides one would be a dependency for four lines of framework API.
 */

import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  children: ReactNode;
  /** What to show instead. Given the error so it can say what went wrong. */
  fallback: (error: Error, retry: () => void) => ReactNode;
  /** Named in the console line, so one boundary's failure is identifiable from another's. */
  what: string;
}

interface State {
  error: Error | null;
}

export class Boundary extends Component<Props, State> {
  override state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  override componentDidCatch(error: Error, info: ErrorInfo) {
    // Logged rather than swallowed. A boundary that renders a tidy message and drops the
    // stack turns a five-minute diagnosis into an afternoon — this one was found by
    // reading exactly this kind of console line.
    console.error(`${this.props.what} failed:`, error, info.componentStack);
  }

  /** Let the caller try again — a transient failure should not need a page reload. */
  private readonly retry = () => this.setState({ error: null });

  override render() {
    const { error } = this.state;
    return error ? this.props.fallback(error, this.retry) : this.props.children;
  }
}
