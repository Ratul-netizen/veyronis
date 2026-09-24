/**
 * The router, the query client, and the one gate between them.
 *
 * # The gate
 *
 * Every route except `/login` renders inside `Authenticated`, which fetches `/me` and
 * sends you to `/login` if that comes back 401. This is a *convenience*, not a
 * protection: the protection is that the server refuses every request without a session,
 * and nothing this file does could weaken or strengthen that. Saying so matters, because
 * a client-side guard that is mistaken for the real one is how an endpoint ends up
 * unprotected on the server "because the UI hides it".
 *
 * # Routes are defined in code
 *
 * TanStack Router's file-based routing generates a route tree into the source directory.
 * That is a build step that writes committed code, and a diff nobody reads. Six routes
 * defined here are six routes anyone can find by opening this file.
 */

import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import {
  Outlet,
  RouterProvider,
  createRootRoute,
  createRoute,
  createRouter,
  useNavigate,
} from "@tanstack/react-router";
import { StrictMode, useEffect } from "react";
import { createRoot } from "react-dom/client";

import { ApiError, api } from "./api";
import { CollectorsPage } from "./collectorspage";
import { PlanPage, RunPage, RunbooksPage, RunsPage } from "./runbookspages";
import { SecurityPage } from "./securitypage";
import { Layout } from "./layout";
import { ExplorePage } from "./explore";
import { FlowPage } from "./flowpage";
import { ServicesPage } from "./servicespage";
import { AcceptInvitePage } from "./acceptinvite";
import { AccountPage } from "./accountpage";
import { AuditPage } from "./auditpage";
import { SloPage } from "./slopage";
import { SubnetsPage } from "./subnetspage";
import { TracePage } from "./tracepage";
import { IncidentsPage } from "./incidentspage";
import { OverviewPage } from "./overview";
import { IngestPage } from "./ingestpage";
import { LoginPage } from "./pages";
import { TenantsPage } from "./tenantspage";
import { UsersPage } from "./userspage";
import { AlertsPage, ChannelsPage, RulesPage } from "./alerts";
import { DashboardPage, DashboardsPage } from "./dashboard";
import {
  DiscoveryCandidatesPage,
  DiscoveryPage,
  DiscoveryRunsPage,
} from "./discoverypages";
import { MapPage } from "./map";
import { TopologyPage } from "./topology";
import { ResourcePage, ResourcesPage } from "./resources";
import { ShellProvider, validateShellSearch } from "./shell";
import "./styles.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // A 401 means the session ended. Retrying it four times delays the redirect to
      // the login page by several seconds and cannot succeed.
      retry: (attempt, error) => !(error instanceof ApiError && error.isUnauthenticated) && attempt < 2,
      staleTime: 30_000,
      refetchOnWindowFocus: false,
    },
  },
});

/** Fetches `/me`, or sends you to sign in. */
function Authenticated() {
  const navigate = useNavigate();
  const me = useQuery({ queryKey: ["me"], queryFn: api.me });

  const unauthenticated = me.isError && me.error instanceof ApiError && me.error.isUnauthenticated;

  useEffect(() => {
    if (unauthenticated) void navigate({ to: "/login" });
  }, [unauthenticated, navigate]);

  if (me.isPending || unauthenticated) return null;

  if (me.isError) {
    return (
      <div className="empty-state">
        <h1>Cannot reach the server</h1>
        <p>{me.error instanceof ApiError ? me.error.message : String(me.error)}</p>
      </div>
    );
  }

  return (
    <ShellProvider me={me.data}>
      <Layout />
    </ShellProvider>
  );
}

const rootRoute = createRootRoute({
  // Validated once, at the root, so every route inherits the tenant and time range and
  // no route has to remember to declare them.
  validateSearch: validateShellSearch,
  component: Outlet,
});

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/login",
  component: LoginPage,
});

// Outside the shell, and deliberately: whoever follows this link has no session, no tenant
// and no navigation to show them. `docs/user-administration.md` §4.1 — the token is the
// whole authorisation.
const invitationRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/invitation/$token",
  component: function Invitation() {
    const { token } = invitationRoute.useParams();
    return <AcceptInvitePage token={token} />;
  },
});

const shellRoute = createRoute({
  getParentRoute: () => rootRoute,
  id: "shell",
  component: Authenticated,
});

const overviewRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/",
  component: OverviewPage,
});

const resourcesRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/resources",
  component: ResourcesPage,
});

const resourceRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/resources/$id",
  component: ResourcePage,
});

const mapRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/map",
  component: MapPage,
});

const flowRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/flow",
  component: FlowPage,
});

const incidentsRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/incidents",
  component: IncidentsPage,
});

const servicesRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/services",
  component: ServicesPage,
});

const exploreRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/explore",
  component: ExplorePage,
});

const alertsRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/alerts",
  component: AlertsPage,
});

const rulesRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/alerts/rules",
  component: RulesPage,
});

const channelsRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/alerts/channels",
  component: ChannelsPage,
});

// Security — M11. Four questions, all of them Query ASTs against `events`; there is no
// security API and this route adds no HTTP surface.
const securityRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/security",
  component: SecurityPage,
});

// Runbooks — M10. Three screens: what exists, what a run would do, and what it did.
const runbooksRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/runbooks",
  component: RunbooksPage,
});

const runbookPlanRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/runbooks/$id",
  component: function RunbookPlan() {
    const { id } = runbookPlanRoute.useParams();
    return <PlanPage id={id} />;
  },
});

const runsRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/runs",
  component: RunsPage,
});

const runRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/runs/$id",
  component: function OneRun() {
    const { id } = runRoute.useParams();
    return <RunPage id={id} />;
  },
});

/**
 * One trace, by id.
 *
 * A detail route with no list above it, and deliberately: there is no "all traces" screen
 * because a list of sampled traces is not a question anybody asks. A trace is reached from
 * something that named it — a log line, a service, a search result — which is why
 * `TraceLink` is exported rather than a menu entry added.
 */
const traceRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/traces/$id",
  component: function OneTrace() {
    const { id } = traceRoute.useParams();
    return <TracePage id={id} />;
  },
});

const auditRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/audit",
  component: AuditPage,
});

const usersRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/users",
  component: UsersPage,
});

const ingestRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/ingest",
  component: IngestPage,
});

const tenantsRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/tenants",
  component: TenantsPage,
});

const accountRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/account",
  component: AccountPage,
});

const slosRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/slos",
  component: SloPage,
});

const subnetsRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/subnets",
  component: SubnetsPage,
});

const topologyRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/topology",
  component: TopologyPage,
});

const discoveryRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/discovery",
  component: DiscoveryPage,
});

const discoveryRunsRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/discovery/runs",
  component: DiscoveryRunsPage,
});

const discoveryCandidatesRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/discovery/candidates",
  component: DiscoveryCandidatesPage,
});

const collectorsRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/collectors",
  component: CollectorsPage,
});

const dashboardsRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/dashboards",
  component: DashboardsPage,
});

const dashboardRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/dashboards/$id",
  component: function Dashboard() {
    // The id comes from the path; the component takes it as a prop so it can be rendered
    // in a test or a story without a router.
    const { id } = dashboardRoute.useParams();
    return <DashboardPage id={id} />;
  },
});

const routeTree = rootRoute.addChildren([
  loginRoute,
  invitationRoute,
  shellRoute.addChildren([
    overviewRoute,
    mapRoute,
    resourcesRoute,
    resourceRoute,
    flowRoute,
    servicesRoute,
    traceRoute,
    subnetsRoute,
    slosRoute,
    auditRoute,
    usersRoute,
    tenantsRoute,
    ingestRoute,
    accountRoute,
    incidentsRoute,
    exploreRoute,
    alertsRoute,
    rulesRoute,
    channelsRoute,
    securityRoute,
    runbooksRoute,
    runbookPlanRoute,
    runsRoute,
    runRoute,
    topologyRoute,
    discoveryRoute,
    discoveryRunsRoute,
    discoveryCandidatesRoute,
    collectorsRoute,
    dashboardsRoute,
    dashboardRoute,
  ]),
]);

const router = createRouter({ routeTree });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

const root = document.getElementById("root");
if (!root) throw new Error("#root is missing from index.html");

createRoot(root).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </StrictMode>,
);
