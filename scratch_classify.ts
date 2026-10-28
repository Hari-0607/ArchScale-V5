import { execSync } from 'child_process';

const commits = ['fdf1367', '4921b0e', 'c1e6f48', '01d348e'];
const regex = /postgres(?:ql)?:\/\/[a-zA-Z0-9_\-\.]+:[^@\s"'`]+@[a-zA-Z0-9_\-\.]+/gi;

for (const hash of commits) {
    const diff = execSync(`git --no-pager show ${hash} --stat -p`, { encoding: 'utf-8', env: { ...process.env, PAGER: 'cat' } });
    const lines = diff.split('\n');
    let currentFile = '';
    for (const l of lines) {
        if (l.startsWith('diff --git ')) {
            currentFile = l.split(' ')[2].replace(/^[ab]\//, '');
        }
        if (l.startsWith('+') && !l.startsWith('+++')) {
            const match = l.match(regex);
            if (match) {
                const isPlaceholder = l.includes('[YOUR-PASSWORD]') ||
                                      l.includes('[YOUR-RUNTIME-PASSWORD]') ||
                                      l.includes(':<password>@') ||
                                      l.includes(':password@') ||
                                      l.includes('test_user:pass') ||
                                      l.includes('postgres:pass') ||
                                      l.includes('archscale_runtime_local_pass');
                const varMatch = l.match(/^\+\s*([A-Za-z0-9_]+)\s*=/);
                const varName = varMatch ? varMatch[1] : (l.includes('ARCHSCALE_TEST_DB_URL') ? 'ARCHSCALE_TEST_DB_URL' : 'in-code');
                console.log(`Commit: ${hash} | File: ${currentFile} | Variable: ${varName} | Classification: ${isPlaceholder ? 'PLACEHOLDER' : 'REAL'}`);
            }
        }
    }
}
