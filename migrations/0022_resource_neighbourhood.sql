-- The other two directions of the graph walk — M9, `docs/M9-incident.md` §2.2 and §2.4.
--
-- 0003 wrote `resource_dependents()` and said why it was written then rather than at M6:
-- *"the correlation engine in M9 cannot be designed against a table that does not
-- exist."* M9 is here, and it turns out to need two more walks over the same edges.
--
-- Both are written for the same reason 0003 gave: so that the cycle guard is written
-- once rather than remembered three times, and so that the tenant is a parameter filtered
-- at every step rather than a predicate a caller has to add.

-- Everything `root` depends on, up to `max_depth` hops. The mirror of
-- `resource_dependents()`.
--
-- # What "upstream" means, and why M9 needs it separately
--
-- §2.4's topology suppression is **directional**: an upstream failure suppresses the
-- notification for a downstream one, and never the reverse. If the hosts go quiet first
-- and their switch a minute later, the switch's alert is *new information* and has to
-- notify.
--
-- `resource_dependents()` answers the downstream question and cannot answer this one:
-- reading its result backwards would tell you that A is downstream of B, which is the
-- same fact from the wrong end and does not help when the walk starts at the alert.
--
-- The edge kinds are the same four, and the direction is the only difference — this
-- follows `source_id = root` to its targets, where dependents follows `target_id` back to
-- its sources.
CREATE FUNCTION resource_dependencies(tenant uuid, root uuid, max_depth int)
RETURNS TABLE (resource_id uuid, depth int, path uuid[])
LANGUAGE sql STABLE
AS $$
    WITH RECURSIVE walk AS (
        -- Anchored on the resource table, so a root belonging to another tenant yields
        -- nothing rather than walking this tenant's edges from a foreign start.
        SELECT r.id AS target_id, 0 AS depth, ARRAY[r.id] AS path
          FROM resource r
         WHERE r.id = resource_dependencies.root
           AND r.tenant_id = resource_dependencies.tenant
        UNION ALL
        SELECT r.target_id, w.depth + 1, w.path || r.target_id
          FROM resource_relationship r
          JOIN walk w ON r.source_id = w.target_id
         WHERE r.tenant_id = resource_dependencies.tenant
           AND r.kind IN ('depends_on', 'member_of', 'hosts', 'runs')
           AND w.depth < max_depth
           AND NOT r.target_id = ANY (w.path)   -- cycle guard, mandatory
    )
    SELECT target_id, depth, path FROM walk;
$$;

-- Everything within `max_depth` hops of `root`, in any direction.
--
-- # Why this is a third function rather than a union of the other two
--
-- §2.2 groups two alerts when their resources are **within N hops**, and proximity there
-- is not directional: an access switch and the host under it are one incident whichever
-- of them failed. A union of the two directed walks is not the same set — it misses
-- anything reached by going *up* and then *down*, which is exactly the shape of two hosts
-- under one switch. Those two hosts are the commonest pair in any cascade, and a union
-- would never group them.
--
-- `connected_to` joins the four kinds here and not in the directed walks, for the same
-- reason: an L2 adjacency has no upstream end, so it says nothing about dependency and
-- everything about proximity.
CREATE FUNCTION resource_neighbourhood(tenant uuid, root uuid, max_depth int)
RETURNS TABLE (resource_id uuid, depth int)
LANGUAGE sql STABLE
AS $$
    WITH RECURSIVE walk AS (
        SELECT r.id AS resource_id, 0 AS depth, ARRAY[r.id] AS path
          FROM resource r
         WHERE r.id = resource_neighbourhood.root
           AND r.tenant_id = resource_neighbourhood.tenant
        UNION ALL
        SELECT e.other, w.depth + 1, w.path || e.other
          FROM walk w
          JOIN LATERAL (
              SELECT r.target_id AS other
                FROM resource_relationship r
               WHERE r.tenant_id = resource_neighbourhood.tenant
                 AND r.source_id = w.resource_id
                 AND r.kind IN ('connected_to', 'depends_on', 'member_of', 'hosts', 'runs')
              UNION ALL
              SELECT r.source_id AS other
                FROM resource_relationship r
               WHERE r.tenant_id = resource_neighbourhood.tenant
                 AND r.target_id = w.resource_id
                 AND r.kind IN ('connected_to', 'depends_on', 'member_of', 'hosts', 'runs')
          ) e ON true
         WHERE w.depth < max_depth
           AND NOT e.other = ANY (w.path)   -- cycle guard, mandatory
    )
    -- A node reachable by two paths appears once per path; the nearest one is the answer,
    -- because §2.2 joins the *nearest* incident and a longer path would misreport it.
    SELECT resource_id, min(depth) AS depth FROM walk GROUP BY resource_id;
$$;

-- # A note on the cycle guards above, because a mutation test survived removing one
--
-- With `max_depth` finite, a walk terminates whether or not the guard is there: the depth
-- bound stops it. The guard bounds the *work* instead — without it a cycle is re-entered
-- once per path, and the number of paths grows exponentially with the depth. At the two
-- hops M9 walks, that is a handful of rows either way, which is why deleting the guard
-- leaves every test in `uops-store-pg/tests/incidents.rs` passing.
--
-- It stays for the reason 0003 gave, which has not changed: the radius is a constant
-- somebody will raise, and the first deep walk over a cycle is the one that hangs an API
-- worker. A guard whose absence is invisible at today's bound is exactly the kind that
-- gets removed during a cleanup.
