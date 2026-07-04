# Synthetic review-only OPA-style baseline policy shape.
# It is intentionally not used to claim production OPA behavior.
package orprg.baseline

default allow := false

allow if {
  input.session_token_valid == true
  input.scope.interface_id == input.request.interface_id
  input.scope.target_id == input.request.target_id
  not input.revocation_confirmed
}
