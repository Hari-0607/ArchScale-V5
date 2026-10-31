import { createApp } from './src/server/index.js';

// Vercel detects this Express export and runs the API as a Node.js Function.
export default createApp();
