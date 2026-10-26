import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createIsolatedTestDatabase } from '../setup/db_connection.js';
import pg from 'pg';

describe('06_immutable_audit: Append-Only Immutable Audit Log', () => {
    let pool: pg.Pool;

    beforeAll(async () => {
        pool = await createIsolatedTestDatabase('test_db_06');
    });

    afterAll(async () => {
        await pool.end();
    });

    it('allows INSERT and SELECT on audit_logs', async () => {
        const insertRes = await pool.query<{ id: string }>(
            `INSERT INTO audit_logs (action, target_entity, target_id, diff)
             VALUES ('test.action', 'test_entity', 'TGT-001', '{"field": "val"}'::jsonb)
             RETURNING id;`
        );
        expect(insertRes.rows.length).toBe(1);

        const selectRes = await pool.query<{ action: string }>(
            `SELECT action FROM audit_logs WHERE id = '${insertRes.rows[0].id}';`
        );
        expect(selectRes.rows[0].action).toBe('test.action');
    });

    it('strictly rejects UPDATE statements on audit_logs via trigger', async () => {
        const logId = (await pool.query<{ id: string }>(
            `INSERT INTO audit_logs (action, target_entity, target_id)
             VALUES ('immutable.update', 'audit', '1') RETURNING id;`
        )).rows[0].id;

        await expect(
            pool.query(`UPDATE audit_logs SET action = 'tampered' WHERE id = '${logId}';`)
        ).rejects.toThrow(/audit log is append-only.*UPDATE and DELETE operations are forbidden/);
    });

    it('strictly rejects DELETE statements on audit_logs via trigger', async () => {
        const logId = (await pool.query<{ id: string }>(
            `INSERT INTO audit_logs (action, target_entity, target_id)
             VALUES ('immutable.delete', 'audit', '2') RETURNING id;`
        )).rows[0].id;

        await expect(
            pool.query(`DELETE FROM audit_logs WHERE id = '${logId}';`)
        ).rejects.toThrow(/audit log is append-only.*UPDATE and DELETE operations are forbidden/);
    });

    it('strictly rejects TRUNCATE statements on audit_logs via trigger', async () => {
        await expect(
            pool.query('TRUNCATE TABLE audit_logs;')
        ).rejects.toThrow(/audit log is append-only.*TRUNCATE is forbidden/);
    });
});
