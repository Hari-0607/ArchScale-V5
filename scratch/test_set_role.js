import pg from 'pg';
const { Client } = pg;

const client = new Client({
    host: '127.0.0.1',
    port: 5433,
    user: 'postgres',
    password: '',
    database: 'archscale_phase1_clean'
});

async function main() {
    await client.connect();
    await client.query('BEGIN;');
    await client.query('SAVEPOINT sp;');

    // Fixture created
    const u = (await client.query("INSERT INTO users (user_code, email) VALUES ('TEST-USR-1', 'test1@test.local') RETURNING id;")).rows[0].id;
    const o = (await client.query("INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('TEST-ORG-1', 'subscriber', 'studio_owner', 'APPLIED') RETURNING id;")).rows[0].id;

    // Switch to runtime role inside the transaction
    await client.query('SET LOCAL ROLE archscale_app_runtime;');
    const current = (await client.query('SELECT current_user, session_user;')).rows[0];
    console.log('Current role in txn:', current);

    try {
        await client.query(`INSERT INTO memberships (user_id, organisation_id, role_key, status) VALUES ('${u}', '${o}', 'business_owner', 'ACTIVE');`);
        console.log('Succeeded illegally!');
    } catch (err) {
        console.log('Rejected with code:', err.code, '| Message:', err.message);
    }

    await client.query('ROLLBACK TO SAVEPOINT sp;');
    await client.query('ROLLBACK;');
    await client.end();
}

main().catch(console.error);
