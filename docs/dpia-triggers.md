# DPIA Triggers (GDPR / UK GDPR)

This repository defaults to data minimization (no raw claims stored server-side), but a DPIA may still be required depending on deployment context.

## When a DPIA is required

Perform a DPIA before deployment if any of the following apply:

- Large-scale processing of credentials for many data subjects
- Systematic monitoring of publicly accessible areas at scale
- Automated decision-making with legal/similarly significant effects
- Use of special category data (health, biometrics, political opinions, etc.)
- Cross-border transfers outside UK/EU without appropriate safeguards
- New technology / novel use of SSI where risks are not well understood
- Use of ZK predicates over potentially sensitive attributes (age gating, eligibility checks) that could enable profiling, exclusion, or systematic monitoring

## Deployment DPIA Template (Minimal)

Copy this section into your deployment repository and fill it in.

### 1. Processing description

- Purpose(s):
- Data subjects:
- Categories of data:
- Systems/components involved:
- Processors/sub-processors (if any):

### 2. Necessity & proportionality

- Why SSI is needed:
- Data minimization measures (hash-only persistence, device-held keys):
- Retention controls:
- Access controls:

### 3. Risks to rights/freedoms

- Threats (replay, credential misuse, correlation, log leakage):
- Likelihood and severity:

### 4. Mitigations

- Replay resistance (one-time challenges, one-time request hashes):
- DID key binding enforced in production posture
- Origin-bound audiences enforced in production posture
- No server-side raw credential/presentation storage
- Log discipline + PII scan gate

### 5. Residual risk & sign-off

- Residual risks:
- Decision:
- Approvals and date:
