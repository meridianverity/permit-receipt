from __future__ import annotations

from typing import Any

from .canonical import digest


def sample_cart() -> list[dict[str, Any]]:
    return [
        {"sku": "sku:book-of-receipts", "name": "Receipt-Gated Commerce Field Guide", "quantity": 1, "unit_price_minor": 4200, "line_total_minor": 4200},
        {"sku": "sku:hardware-key", "name": "Demo hardware-bound wallet key", "quantity": 1, "unit_price_minor": 5900, "line_total_minor": 5900},
    ]


def cart_total(cart: list[dict[str, Any]]) -> int:
    return sum(int(line["line_total_minor"]) for line in cart)


def make_payment_action(sensor_core_digest: str, *, total_minor: int | None = None, cart: list[dict[str, Any]] | None = None, idempotency_key: str = "idem:demo:001") -> dict[str, Any]:
    cart = cart or sample_cart()
    subtotal = cart_total(cart)
    tax = 707
    shipping = 0
    computed_total = subtotal + tax + shipping
    total = computed_total if total_minor is None else total_minor
    return {
        "type": "PaymentAction",
        "version": "1.0",
        "tenant_id": "tenant:acme-demo",
        "agent_id": "agent:shopping-copilot-001",
        "purpose_id": "agentic_commerce.checkout",
        "merchant": {
            "merchant_id": "merchant:demo-books",
            "display_name": "Demo Books Merchant",
        },
        "cart": cart,
        "totals": {
            "currency": "USD",
            "subtotal_minor": subtotal,
            "tax_minor": tax,
            "shipping_minor": shipping,
            "discount_minor": 0,
            "total_minor": total,
        },
        "payment": {
            "capture_mode": "AUTHORIZE_THEN_CAPTURE",
            "idempotency_key": idempotency_key,
            "instrument_ref": "tok:demo-wallet:customer-001:default-card",
        },
        "context": {
            "sensor_receipt_core_digest": sensor_core_digest,
            "agent_plan_digest": digest({"plan": "buy exact cart only", "merchant": "merchant:demo-books"}),
            "commerce_session_id": "session:demo-checkout-001",
        },
    }
