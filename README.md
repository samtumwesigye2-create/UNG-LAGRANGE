# UNG-LAGRANGE

Internal authenticated transport and service-relay layer for the UNG systems portfolio.

## Recovered production contract

This repository was reconstructed from the surviving Railway production configuration and deployment history. The existing production service is intentionally not modified by this recovery commit.

Responsibilities:
- authenticated inter-service relay
- service registration/discovery
- destination lookup
- delivery correlation
- persistent relay/audit state
- universal transport adapter boundary

Production evidence identifies `/health` and `/v1/relay` as live endpoints. NEXUS is a known relay client.

## Separation of responsibilities

LAGRANGE handles internal UNG service transport. GOVBRIDGE handles interoperability, schema/protocol translation, and controlled legacy/external integration.

## Security

Relay credentials are supplied only through deployment environment variables. Never commit service secrets.
