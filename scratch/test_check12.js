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

    const o = (await client.query("INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('O12B', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;")).rows[0].id;
    
    await client.query('SET LOCAL ROLE archscale_app_runtime;');
    const r1 = await client.query(`UPDATE organisations SET status = 'SUSPENDED' WHERE id = '${o}';`);
    console.log('rowCount as runtime:', r1.rowCount);

    await client.query('RESET ROLE;');
    const r2 = await client.query(`UPDATE organisations SET status = 'SUSPENDED' WHERE id = '${o}';`);
    console.log('rowCount as postgres:', r2.rowCount);

    await client.query('ROLLBACK;');
    await client.end();
}

main().catch(console.error);
