# Hosted Starter API and SDK client

This path uses the same verified owner, Checkout, and paid tenant as OpenClaw. It works with the documented HTTP API and with SDKs that accept `clientId` and `clientSecret`. A paid or valid prepaid owner approves a short code in the Portal; the secret is generated and retained on the client machine.

1. Open [Hosted Starter](https://portal.try.getaxonflow.com/hosted/start), verify your email, review the displayed limits, and complete Checkout.
2. On the machine that will make API calls, run:

   ```bash
   curl -fsSLo hosted-api-link.mjs https://portal.try.getaxonflow.com/hosted-api-link.mjs
   node hosted-api-link.mjs
   ```

   The same download is linked on the Portal page. The command displays a 10-character code. Enter it under **Link your client** in the Portal. The command saves `~/.config/axonflow/hosted-api.json` with mode `0600`. Each linked client has its own credential. The owner can list and revoke it in the Portal. To deliberately switch this machine to a different account, run with `--replace`.
3. A TypeScript SDK process can read that local file and pass its values into the [published SDK](typescript-quickstart.md):

   ```typescript
   import { readFileSync } from 'node:fs';
   import { homedir } from 'node:os';
   import { join } from 'node:path';
   import { AxonFlow } from '@axonflow/sdk';

   const linked = JSON.parse(readFileSync(join(homedir(), '.config', 'axonflow', 'hosted-api.json'), 'utf8'));
   const client = new AxonFlow({
     endpoint: linked.endpoint,
     clientId: linked.clientId,
     clientSecret: linked.clientSecret,
   });
   // Pass client to your existing proxy or gateway integration.
   ```

   For a raw HTTP request, pass the same values as Basic credentials and a stable `X-Axonflow-Event-ID` for retries of one logical event. For example, this gateway pre-check uses the linked credential and stops on any non-2xx response:

   ```javascript
   const response = await fetch(`${linked.endpoint}/api/policy/pre-check`, {
     method: 'POST',
     headers: {
       Authorization: `Basic ${Buffer.from(`${linked.clientId}:${linked.clientSecret}`).toString('base64')}`,
       'Content-Type': 'application/json',
       'X-Axonflow-Event-ID': 'your-stable-event-id',
     },
     body: JSON.stringify({ user_token: 'your-user', client_id: linked.clientId, query: 'your query' }),
   });
   if (!response.ok) throw new Error(`Governance refused: HTTP ${response.status}`);
   const decision = await response.json();
   if (!decision.approved) throw new Error('Governance denied this request');
   ```

The default Agent is `https://try.getaxonflow.com`. For staging, specify **both** `--portal` and `--endpoint` HTTPS origins while linking; the saved credential keeps the matching Agent origin. Do not copy the credential file into a repository or share it between users. A `402` means the tenant needs payment or recovery in the Portal; do not continue the governed action after that response. Self-hosted Community deployments continue to use their own local configuration.

The linked path is source-ready in this repository. Operators must deploy the Portal/Agent change and verify it with released client builds before advertising it as generally available.
