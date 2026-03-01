# Hedera Fee Budgets (Self-Funded Flows)

Self-funded onboarding flows are user-paid and must be safe-by-default:

- Explicit fee caps
- Explicit transaction byte caps
- Deterministic failure when exceeded (no silent submits)

## Where Caps Are Enforced

- `app-gateway` enforces caps on `POST /v1/onboard/did/create/user-pays/submit`
- Wallets/clients should set `maxTransactionFee` when constructing transactions client-side

## Configuration

Legacy knobs (still supported):

- `USER_PAYS_MAX_TX_BYTES`
- `USER_PAYS_MAX_FEE_TINYBARS`

Data-driven budgets (recommended):

- `USER_PAYS_FEE_BUDGETS_JSON`

Example:

```json
{
  "TopicMessageSubmitTransaction": {
    "maxFeeTinybars": 50000000,
    "maxTxBytes": 32768
  }
}
```

## Transparency

Wallets can fetch:

- `GET /v1/capabilities`

This includes the current fee/size caps and fee budgets (no secrets, no PII).

## Behavior When Exceeded

- Byte cap exceeded → HTTP `413` (request too large)
- Fee cap exceeded → HTTP `400` (invalid request)
- Unsupported tx type → HTTP `400`
