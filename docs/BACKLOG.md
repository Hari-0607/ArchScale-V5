# Backlog

Items deferred from Phase 1 close-out and Phase 2 Step 2. Not started unless a later prompt says so.

1. **Untrack `node_modules` and the Vitest cache**  
   `.gitignore` already lists `node_modules/` and `.vitest/`. If either is still in the git index, remove them from tracking without deleting local files (`git rm -r --cached`). Do not run that until asked.

2. **Full staging rebuild and `staging_verify` run**  
   End of Phase 2 only. Rebuild staging from migrations, then run `scripts/staging_verify.ts`. Not during Step 2.

3. **40-sample timing test**  
   `tests/staging/timing_spread.test.ts` / `scripts/measure_timing_paths.ts`. Run only when a change touches sign-in, or at the Phase 2 close-out the user names.

4. **Staging pool certificate verification**  
   Runtime and admin pools currently use `ssl: { rejectUnauthorized: false }`. Switch to verifying the staging CA when the certificate source is agreed.

5. **Remove the hardcoded fallback password in `src/db/index.ts`**  
   Local test pool still falls back to a literal password when `ARCHSCALE_LOCAL_RUNTIME_PASSWORD` is unset. Tests should fail closed if the env var is missing.

6. **`user_code` collision retry**  
   `fn_upsert_user_mirror` generates `AS-` + 8 hex chars and inserts without retrying a unique violation on `users.user_code`. Add a bounded retry (or a collision-safe generator) in a later migration.

7. **Member directory (org-wide membership reads)**  
   Org-wide membership reads need a permission-gated definer function (e.g. `org.members.read`) rather than open or broad table SELECT on `memberships`. Deferred to Step 3.
