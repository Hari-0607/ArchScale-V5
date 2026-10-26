import { PGlite } from '@electric-sql/pglite';
import * as fs from 'fs';
import * as path from 'path';

export async function createTestDatabase() {
    const db = new PGlite();

    const migrationFiles = [
        '001_core_types_and_identities.sql',
        '002_ecosystem_apps_and_entitlements.sql',
        '003_data_driven_roles_and_permissions.sql',
        '004_workspaces_memberships_and_contexts.sql'
    ];

    for (const file of migrationFiles) {
        const filePath = path.join(__dirname, '../../migrations', file);
        const sql = fs.readFileSync(filePath, 'utf-8');
        await db.exec(sql);
    }

    return db;
}
