# Pay.com Phase 2 — Secure Working MVP

This version turns the static prototype into a real server-backed application.

Included: real database-backed users, hashed PINs, secure sessions, CSRF protection, rate limiting, user verification, transaction records, receipt metadata, payout-account records, admin controls, audit logs, PostgreSQL support, and Render deployment config.

Important: this is not connected to a bank, IMTO, FX provider, KYC vendor, or payout rail. No real funds should be accepted until regulated integrations and compliance are complete.

Render deployment: upload these files to the PAYCOM GitHub repository, then use Render Blueprint or Web Service + PostgreSQL. Set ADMIN_PHONE and ADMIN_PIN as environment variables.
