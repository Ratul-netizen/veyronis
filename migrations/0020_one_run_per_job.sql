-- A discovery job may have one run in flight, and the schema is what says so.
--
-- The scheduler has to guarantee that a job due at 02:00 is not swept twice — once by
-- each of two server replicas, or twice by one server whose previous sweep has not
-- finished because the estate is large. Doing that in the application means a check and
-- an insert with a gap between them, and the gap is exactly where the second caller gets
-- in.
--
-- A partial unique index closes it. The second INSERT fails with 23505, which the store
-- already maps to `Invalid`, and the scheduler reads that as "somebody else has this
-- one" rather than as an error worth reporting.
--
-- # Why the predicate is what it is
--
-- `status = 'running'` only: a finished run is history and a job accumulates thousands of
-- them, so a unique index over all of them would forbid the second nightly sweep from
-- ever happening.
--
-- `job_id IS NOT NULL` because an ad-hoc run — an operator probing one address from the
-- candidate list — has no job behind it, and several of those at once is a normal thing
-- to want. NULLs are distinct in a unique index anyway; the predicate says so out loud
-- and keeps the index off rows it will never be asked about.
--
-- `tenant_id` first because every index in this schema leads with it, and because two
-- customers of one MSP having a job with the same uuid is impossible but an index that
-- relies on that is an index resting on an assumption.

CREATE UNIQUE INDEX discovery_run_one_in_flight_per_job
    ON discovery_run (tenant_id, job_id)
 WHERE status = 'running' AND job_id IS NOT NULL;
