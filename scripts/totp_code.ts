import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { generateTotpCode } from '../src/utils/totp.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function main() {
    const args = process.argv.slice(2);
    if (!args.includes('--confirm-local')) {
        console.error('ABORTED: Refusing to run without --confirm-local flag.');
        process.exit(1);
    }

    const userKey = args.find(a => !a.startsWith('--'));
    if (!userKey) {
        console.error('Usage: npx tsx scripts/totp_code.ts <user-key> --confirm-local');
        console.error('Example keys: founder, client_servicing, business_owner, multi_membership');
        process.exit(1);
    }

    const testUsersPath = path.join(__dirname, '../.local/test-users.json');
    if (!fs.existsSync(testUsersPath)) {
        console.error('ABORTED: .local/test-users.json does not exist. Run scripts/seed_staging_users.ts first.');
        process.exit(1);
    }

    const testUsers = JSON.parse(fs.readFileSync(testUsersPath, 'utf-8'));
    const user = testUsers[userKey];
    if (!user) {
        console.error(`User key "${userKey}" not found in test-users.json.`);
        process.exit(1);
    }

    if (!user.totpSecret) {
        console.error(`User "${userKey}" does not have an enrolled TOTP factor.`);
        process.exit(1);
    }

    // Prints ONLY the current 6-digit TOTP code (never secrets or tokens)
    const code = generateTotpCode(user.totpSecret);
    console.log(code);
}

main();

