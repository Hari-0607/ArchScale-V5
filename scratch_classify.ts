import { execSync } from 'child_process';

const commits = execSync('git --no-pager log --oneline', { encoding: 'utf-8', env: { ...process.env, PAGER: 'cat' } }).trim().split('\n');

const regex = /postgres(?:ql)?:\/\/[a-zA-Z0-9_\-\.]+:[^@\s"'`]+@[a-zA-Z0-9_\-\.]+/gi;

console.log('=== CONNECTION STRING CLASSIFICATION IN GIT HISTORY ===');

for (const line of commits) {
    const hash = line.split(' ')[0];
    const diff = execSync(`git --no-pager show ${hash}`, { encoding: 'utf-8', env: { ...process.env, PAGER: 'cat' } });
    const matches = diff.match(regex);
    if (!matches) continue;

    // Split diff into files
    const fileDiffs = diff.split('diff --git ');
    for (const fileDiff of fileDiffs) {
        if (!fileDiff.trim()) continue;
        const fileMatch = fileDiff.match(/^[ab]\/([^\s]+)/m);
        const fileName = fileMatch ? fileMatch[1] : 'unknown';

        const linesInFile = fileDiff.split('\n');
        for (const l of linesInFile) {
            if (!l.startsWith('+') && !l.startsWith('-')) continue;
            if (l.startsWith('+++') || l.startsWith('---')) continue;

            const m = l.match(regex);
            if (m) {
                // Classify by structure only
                // Placeholders: contains [YOUR-PASSWORD], <password>, password, your-super-secret, postgres:postgres
                const isPlaceholder = l.includes('[YOUR-PASSWORD]') ||
                                      l.includes(':<password>@') ||
                                      l.includes(':password@') ||
                                      l.includes('your-super-secret');

                const classification = isPlaceholder ? 'PLACEHOLDER' : 'REAL';
                const varMatch = l.match(/^[\+\-]?\s*([A-Za-z0-9_]+)\s*=/);
                const varName = varMatch ? varMatch[1] : (l.includes('connectionString') ? 'connectionString' : 'in-code');

                console.log(`Commit: ${hash} | File: ${fileName} | Variable: ${varName} | Classification: ${classification}`);
            }
        }
    }
}
