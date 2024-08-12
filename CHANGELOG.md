## v0.1.0
- Initial fork of the [ansible-community/ansible-vault] role. Initial goal was to adapt the role for use with OpenBao and to reduce complexity.
  - modified and adapted role to employ OpenBao Vault instead of Hashicorp Vault.
  - removed several vault-backend options
  - removed several supported linux distros
  - removed auto-unseal options
  - 