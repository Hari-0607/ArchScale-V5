# Agent Rules — ArchScale V05

These rules govern all autonomous and interactive engineering actions in this repository.

1. **Secrets & Credentials**
   - Never print, quote, or echo secrets, connection strings, JWTs, or raw `.env` lines in outputs, terminal commands, or artifacts.
   - Always redact database error messages that might interpolate connection strings or credentials before printing.

2. **Staging Environment Access & Modifications**
   - No writes to staging except what the user explicitly approves in prompt instructions.
   - No migrations may be permanently applied to staging without explicit approval.
   - Any approved staging validation must run strictly inside an isolated transaction that rolls back (`BEGIN; ... ROLLBACK;`).

3. **Git & Version Control**
   - Do not commit or push to git remotes.
   - Leave all changes uncommitted in the working tree and report precisely what files were modified or created.

4. **Instruction Recovery**
   - Do not inspect transcript/conversation logs to recover past instructions; ask the user directly when clarification is required.
