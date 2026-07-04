// Synthetic review-only Cedar-like policy shape. Not a production Cedar corpus.
permit(
  principal,
  action == Action::"InvokeTool",
  resource
)
when {
  context.has_receipt == true &&
  context.action_digest_match == true &&
  context.epoch_current == true &&
  context.revocation_fresh == true
};
