# Security

ownerwatch is read-only: it never holds keys and never sends transactions. The hosted-tier contract in `contracts/` does hold customer USDC until the operator withdraws it.

If you find a vulnerability in ownerwatch or the Subscriptions contract, open a private security advisory on GitHub (Security tab, "Report a vulnerability") or email the address on the maintainer's GitHub profile. Please don't open a public issue for it. You'll get a reply within 72 hours.

If `ownerwatch probe` shows you something alarming about a protocol that isn't yours, tell that protocol privately. Don't post it.
