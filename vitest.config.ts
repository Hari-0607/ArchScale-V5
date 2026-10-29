import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        testTimeout: 30000,
        hookTimeout: 30000,
        fileParallelism: false, // Run migration test files sequentially for clean database creation
        environment: 'node',
        include: ['tests/**/*.test.ts']
    }
});
