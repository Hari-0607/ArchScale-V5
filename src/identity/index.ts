import { config } from '../config/env.js';
import { IdentityProvider } from './types.js';
import { SupabaseProvider } from './providers/supabase.js';
import { LocalProvider } from './providers/local.js';

let defaultProvider: IdentityProvider | null = null;

export function getIdentityProvider(): IdentityProvider {
    if (!defaultProvider) {
        if (config.nodeEnv === 'test' && config.allowLocalAuth) {
            defaultProvider = new LocalProvider();
        } else {
            defaultProvider = new SupabaseProvider();
        }
    }
    return defaultProvider;
}

export * from './types.js';
export { SupabaseProvider } from './providers/supabase.js';
export { LocalProvider } from './providers/local.js';
