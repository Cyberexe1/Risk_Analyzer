"""
The rupee cost of every decision outcome.

Recall without a cost model is a vanity metric: a detector that flags 20% of
traffic to catch all fraud destroys more value than the fraud did. These constants
are what turn a confusion matrix into a business answer.

Figures are industry-typical estimates for a mid-size Indian D2C merchant with an
average order value near Rs 2,400. They are NOT audited figures from a real
merchant, and the churn term in particular is soft -- see sensitivity() below.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict

AOV = 2400.0
CONTRIBUTION_MARGIN = 0.12
CUSTOMER_LIFETIME_VALUE = 5750.0
CHURN_PROB_AFTER_WRONG_BLOCK = 0.20


@dataclass(frozen=True)
class CostModel:
    # Fraud we allowed through: goods gone, plus the bank's chargeback fee and
    # the staff time to handle the dispute.
    fraud_loss: float = AOV + 750.0 + 400.0            # 3550

    # An analyst at ~Rs 42,000/month spending ~3 minutes on a case, loaded.
    # Paid on every review, right or wrong.
    review_cost: float = 35.0

    # A real customer we declined. Lost margin now, plus the expected value of
    # them never coming back. This is the number that constrains the whole design.
    block_legit_cost: float = (
        AOV * CONTRIBUTION_MARGIN
        + CUSTOMER_LIFETIME_VALUE * CHURN_PROB_AFTER_WRONG_BLOCK
    )                                                   # 1438

    # Fraud we blocked: no loss. The avoided fraud_loss is the benefit.
    fraud_blocked_cost: float = 0.0

    # --- promo gate ---
    promo_value: float = 500.0
    promo_wrong_deny_cost: float = 500.0 + 260.0        # offer withheld + goodwill
    promo_review_cost: float = 35.0

    def as_dict(self) -> dict:
        d = asdict(self)
        d["block_to_review_ratio"] = round(self.block_legit_cost / self.review_cost, 1)
        return d


COSTS = CostModel()


def transaction_cost(
    tp_block: int, tp_review: int, fp_block: int, fp_review: int, fn: int,
    c: CostModel = COSTS,
) -> float:
    """Total cost of one operating point.

    tp_block  fraud correctly blocked      -> 0
    tp_review fraud sent to review, caught -> review cost only
    fp_block  legit wrongly blocked        -> the expensive error
    fp_review legit sent to review         -> cheap friction
    fn        fraud allowed through        -> full loss
    """
    return (
        tp_block * c.fraud_blocked_cost
        + tp_review * c.review_cost
        + fp_block * c.block_legit_cost
        + fp_review * c.review_cost
        + fn * c.fraud_loss
    )


def do_nothing_cost(n_fraud: int, c: CostModel = COSTS) -> float:
    """Baseline: allow everything. Every fraud becomes a full loss."""
    return n_fraud * c.fraud_loss


def sensitivity() -> dict:
    """The churn term is the softest input. Halving and doubling it shows whether
    conclusions survive -- net saving does, the optimal block threshold does not.
    """
    out = {}
    for label, churn in (("optimistic", 0.10), ("used", 0.20), ("pessimistic", 0.40)):
        cost = AOV * CONTRIBUTION_MARGIN + CUSTOMER_LIFETIME_VALUE * churn
        out[label] = {
            "churn_prob": churn,
            "block_legit_cost": round(cost, 2),
            "block_to_review_ratio": round(cost / COSTS.review_cost, 1),
        }
    return out
