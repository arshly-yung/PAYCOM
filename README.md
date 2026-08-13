# PAYCOM V3 COMPLETE

This is an upgrade of the existing working PAYCOM project, not a replacement concept.

Preserved:
- PostgreSQL persistence
- existing User / Transaction tables
- admin approval
- customer login
- transaction creation
- manual receiving details per transaction
- receipt upload
- audit logs
- Render/Gunicorn deployment structure

Added:
1. Mandatory email on new registration.
2. 6-digit email verification code.
3. Green verified badge after email confirmation.
4. Japan transaction tiers:
   - ¥10,000–¥500,000: approved Pay.com account + verified email.
   - ¥510,000–¥1,000,000: approved Pay.com account + verified email + admin-approved ID.
5. NIN / Driver's License submission.
6. Admin ID review with Approve / Decline.
7. Identity documents stored encrypted in PostgreSQL.
8. Original anime-style avatar choices.
9. Animated Pay.com landing screen.
10. Persistent receipt files encrypted in PostgreSQL.
11. Nigerian payout bank details supplied by customer after PAYMENT_VERIFIED.
12. Admin enters gross NGN value and Pay.com fee percentage.
13. System calculates fee and net payout.
14. Admin starts manual payout.
15. Admin records actual NGN amount sent and real bank transfer reference.
16. COMPLETED status cannot be selected manually without the payout workflow.
17. Customer sees fee, net payout, payout bank and completion information.

## IMPORTANT DATABASE DESIGN
This version does NOT remove or alter the existing User, Transaction, ReceivingInstruction,
Receipt or AuditLog columns. New features use NEW tables:
- user_profile
- identity_document
- receipt_file
- payout_request

`db.create_all()` creates these new tables while keeping existing PostgreSQL customer and
transaction records.

## EMAIL ACTIVATION
For actual email codes, add these Render Environment Variables to PAYCOM-API:

SMTP_HOST
SMTP_PORT
SMTP_USER
SMTP_PASSWORD
SMTP_FROM

For Gmail testing:
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=<your Gmail>
SMTP_PASSWORD=<Google App Password, NOT your normal Gmail password>
SMTP_FROM=<your Gmail>

Optional:
PAYCOM_FEE_PERCENT=10

Optional but recommended:
DOCUMENT_ENCRYPTION_KEY=<a Fernet key>
If not set, the app derives an encryption key from SECRET_KEY.

Do NOT set EMAIL_TEST_MODE=1 on a public deployment. That mode only logs verification
codes for development.

## DEPLOYMENT
Upload all files/folders in this ZIP to the existing arshly-yung/PAYCOM repository,
commit to main, then deploy latest commit on PAYCOM-API.

The existing DATABASE_URL, ADMIN_PHONE and ADMIN_PIN on Render must be kept unchanged.
