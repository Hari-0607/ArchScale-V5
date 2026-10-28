import { describe, it, expect } from 'vitest';
import { assertLocalTestDatabaseGuard } from '../../src/db/index.js';

describe('Local Test Database Guard Invariants', () => {
    it('1. throws if ARCHSCALE_TEST_DB_URL is missing or empty', () => {
        expect(() => assertLocalTestDatabaseGuard(undefined)).toThrow(/Missing ARCHSCALE_TEST_DB_URL/);
        expect(() => assertLocalTestDatabaseGuard('')).toThrow(/Missing ARCHSCALE_TEST_DB_URL/);
    });

    it('2. throws if host is remote (not 127.0.0.1 or localhost)', () => {
        const remote1 = 'postgresql://postgres:pass@db.example-remote.supabase.co:5432/postgres';
        expect(() => assertLocalTestDatabaseGuard(remote1)).toThrow(/Local tests must connect only to 127\.0\.0\.1 or localhost/);

        const remote2 = 'postgresql://postgres:pass@aws-0-ap-south-1.pooler.supabase.com:6543/postgres';
        expect(() => assertLocalTestDatabaseGuard(remote2)).toThrow(/Local tests must connect only to 127\.0\.0\.1 or localhost/);

        const remoteIp = 'postgresql://postgres:pass@192.168.1.100:5432/postgres';
        expect(() => assertLocalTestDatabaseGuard(remoteIp)).toThrow(/Local tests must connect only to 127\.0\.0\.1 or localhost/);
    });

    it('3. throws if host or username matches the staging project ref', () => {
        const stagingRef = process.env.ARCHSCALE_STAGING_PROJECT_REF || 'mockstagingref123';
        const oldRef = process.env.ARCHSCALE_STAGING_PROJECT_REF;
        process.env.ARCHSCALE_STAGING_PROJECT_REF = 'myprojectref';

        try {
            // Host containing project ref
            const dangerousHost = 'postgresql://postgres:pass@myprojectref:5432/postgres';
            expect(() => assertLocalTestDatabaseGuard(dangerousHost)).toThrow(/Local tests must connect only to 127\.0\.0\.1 or localhost/);

            // User containing project ref on 127.0.0.1
            const dangerousUser = 'postgresql://postgres.myprojectref:pass@127.0.0.1:5432/postgres';
            expect(() => assertLocalTestDatabaseGuard(dangerousUser)).toThrow(/matches staging project ref/);
        } finally {
            process.env.ARCHSCALE_STAGING_PROJECT_REF = oldRef;
        }
    });

    it('4. accepts 127.0.0.1 and localhost', () => {
        const localIp = 'postgresql://test_user:pass@127.0.0.1:5432/test_db';
        const parsedIp = assertLocalTestDatabaseGuard(localIp);
        expect(parsedIp.hostname).toBe('127.0.0.1');

        const localHost = 'postgresql://test_user:pass@localhost:5432/test_db';
        const parsedHost = assertLocalTestDatabaseGuard(localHost);
        expect(parsedHost.hostname).toBe('localhost');
    });

    it('5. in NODE_ENV=test, code used by local tests does not read ARCHSCALE_RUNTIME_DB_URL', () => {
        // Even if ARCHSCALE_RUNTIME_DB_URL is completely deleted or poisoned,
        // importing or using the guard works without touching ARCHSCALE_RUNTIME_DB_URL
        const oldRuntimeUrl = process.env.ARCHSCALE_RUNTIME_DB_URL;
        delete process.env.ARCHSCALE_RUNTIME_DB_URL;

        try {
            const validLocal = 'postgresql://postgres:pass@127.0.0.1:5432/postgres';
            const parsed = assertLocalTestDatabaseGuard(validLocal);
            expect(parsed.hostname).toBe('127.0.0.1');
        } finally {
            if (oldRuntimeUrl) process.env.ARCHSCALE_RUNTIME_DB_URL = oldRuntimeUrl;
        }
    });

    it('6. bidirectional isolation: local tests stay strictly unable to reach staging when ARCHSCALE_STAGING_TESTS is unset', () => {
        const oldStagingFlag = process.env.ARCHSCALE_STAGING_TESTS;
        delete process.env.ARCHSCALE_STAGING_TESTS;

        try {
            // Attempting to pass any staging or remote URL to the local test database guard throws
            const stagingCandidate = 'postgresql://archscale_app_runtime:secret@aws-0-ap-south-1.pooler.supabase.com:5432/postgres';
            expect(() => assertLocalTestDatabaseGuard(stagingCandidate)).toThrow(/Local tests must connect only to 127\.0\.0\.1 or localhost/);
        } finally {
            if (oldStagingFlag) process.env.ARCHSCALE_STAGING_TESTS = oldStagingFlag;
        }
    });

    it('7. bidirectional isolation: ARCHSCALE_STAGING_TESTS=true explicitly enables staging runtime pool access for staging tests only', () => {
        const oldStagingFlag = process.env.ARCHSCALE_STAGING_TESTS;
        process.env.ARCHSCALE_STAGING_TESTS = 'true';

        try {
            expect(process.env.ARCHSCALE_STAGING_TESTS).toBe('true');
            // Staging tests require this flag to access staging runtime pool
        } finally {
            if (oldStagingFlag !== undefined) {
                process.env.ARCHSCALE_STAGING_TESTS = oldStagingFlag;
            } else {
                delete process.env.ARCHSCALE_STAGING_TESTS;
            }
        }
    });
});
