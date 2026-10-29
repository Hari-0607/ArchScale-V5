const pg = require('pg');
const client = new pg.Client({ host: 'localhost', port: 5432, user: 'postgres', database: 'archscale_test_014' });
async function run() {
    await client.connect();
    const res = await client.query(`
        SELECT column_name, data_type, is_nullable, column_default
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'invitations'
        ORDER BY ordinal_position;
    `);
    console.table(res.rows);
    await client.end();
}
run().catch(console.error);

