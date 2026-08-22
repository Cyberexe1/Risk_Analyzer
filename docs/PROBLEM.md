# FraudShield — The Problem

Read this first. No architecture, no models, no metrics jargon. Just what the merchant is losing money to and why it is hard to stop.

---

## 1. The normal case

You own an online business. You sell a Rs 5,000 product.

```text
Customer
   |
   v  pays Rs 5,000
Payment succeeds
   |
   v
You ship the product
```

Money in, goods out. Nothing to solve here. This is the 97% of traffic that must stay frictionless — every control we add is a tax on this path, and that tax is the whole reason the problem is hard.

---

## 2. Three ways the merchant loses money

### Loss 1 — Stolen payment method

Someone pays Rs 20,000 with a card that isn't theirs.

```text
Payment successful   [OK]
   |
   v
Merchant ships the product
   |
   v  ...weeks later
Real cardholder disputes the charge
   |
   v
Bank reverses the payment
```

The merchant loses:

| Item | Amount |
| --- | --- |
| Product value | Rs 20,000 |
| Shipping | Rs 400 |
| Chargeback fee | Rs 750 |
| Staff time handling the dispute | Rs 400 |
| **Total** | **Rs 21,550** |

The payment *succeeded*. The gateway said yes. Nothing at the moment of sale looked wrong. The loss arrives weeks later, by which time the goods are gone.

**The question:** can we identify this transaction as risky *before* we ship?

### Loss 2 — One person, many accounts

The merchant runs a Rs 500 welcome cashback to attract new customers.

```text
Account 1  ->  Rs 500 cashback
Account 2  ->  Rs 500 cashback
Account 3  ->  Rs 500 cashback
Account 4  ->  Rs 500 cashback
Account 5  ->  Rs 500 cashback
```

The dashboard shows five new customers and Rs 2,500 of acquisition spend. Looks like the promotion is working.

It isn't. It's one person:

```text
Account 1 --+
Account 2 --+
Account 3 --+--- same device ---- same IP
Account 4 --+
Account 5 --+
```

Examine any single account and it looks fine: a real email, a plausible name, a small first order. Examine them together and the pattern is obvious. **This is why the loss is invisible to per-transaction checks** — the evidence exists only in the relationships *between* accounts, and a system that scores one transaction at a time is structurally blind to it.

That's coordinated abuse. Marketing budget leaking to one person while the merchant congratulates itself on growth.

### Loss 3 — Behaviour that suddenly doesn't fit

An account normally makes one or two payments a day. Then:

```text
10:01   Rs 9,999   success
10:02   Rs 9,999   failed
10:02   Rs 9,999   failed
10:03   Rs 9,999   success
10:03   Rs 9,999   failed
10:04   Rs 9,999   success
10:05   Rs 9,999   success
10:06   Rs 9,999   success
```

Eight attempts in six minutes. Repeated failures mixed with successes. Amounts sitting just under a round number.

Nothing here is impossible for a real customer. A person could genuinely buy five things in six minutes. But it is *very different from what this account has always done*, and that difference is the signal.

Note what makes this detectable: not the amount, not the count, but the **gap between this behaviour and this account's own history**. A flat rule like "over Rs 10,000 is suspicious" would miss all of it — every charge is Rs 9,999.

---

## 3. What the merchant is actually asking

Strip away the examples and it's one sentence:

> "I have thousands of transactions a day. Which ones are likely to cost me money, and how do I find out before they do?"

That's the job. FraudShield is the security guard on the merchant's payments.

---

## 4. The second problem — and it's the harder one

Suppose FraudShield gets aggressive. Out of 1,000 transactions:

```text
950 legitimate
 50 fraudulent
```

It decides to block anything that looks suspicious. It catches all 50. It also flags 100 real customers.

The merchant now has a *new* problem:

- 100 genuine customers were refused
- that revenue is gone
- some of those customers won't come back
- someone has to manually sort through the pile

Those 100 are **false positives**. And here's the part that gets missed: a false positive can cost more than the fraud it was trying to prevent. Blocking a real customer costs the lost margin *plus* the chance they never return. Our cost model puts that at roughly **Rs 1,438 per wrongly blocked customer**, against **Rs 35** for sending a transaction to a human for a two-minute look.

Blocking is about 41x more expensive per mistake than reviewing. That single ratio drives the entire design: FraudShield routes most risk to a human queue and reserves outright blocking for the small set of cases where the evidence is overwhelming.

### So the real problem is a balance

```text
                    RISK DECISION
                          |
          +---------------+---------------+
          v                               v
    Catch the fraud                Leave genuine
                                 customers alone
```

Too lenient, fraud gets through. Too aggressive, real customers get hurt. The goal:

> Catch as much genuine fraud as possible while disturbing as few legitimate customers as possible.

This is exactly why the track asks for precision, recall **and** false-positive cost. Any one of those alone can be gamed. Together they describe the actual trade-off.

---

## 5. Precision and recall, in plain numbers

100 transactions:

```text
90 genuine
10 fraudulent
```

FraudShield flags 12 as suspicious. Of those 12:

```text
 9 were actually fraud
 3 were genuine customers
```

**Recall** — of the 10 real fraud cases, we caught 9.

```text
recall = 9 / 10 = 90%
```

*Did we catch the bad stuff?*

**Precision** — of the 12 we flagged, 9 were right.

```text
precision = 9 / 12 = 75%
```

*When we raised an alarm, were we correct?*

Those **3 genuine customers are the false positives**. They're the cost of the 90% recall. You cannot read either number alone:

- A system that flags every transaction gets **100% recall** and useless precision.
- A system that flags one transaction it's certain about gets **100% precision** and catches almost nothing.

The honest question is always: what did this recall cost in false positives, and what did those false positives cost in rupees?

---

## 6. Why this needs to be automated

A merchant processing 10,000 payments a day cannot look at 10,000 payments a day.

```text
10,000 transactions
        |
        v
   FraudShield
        |
   +----+----+
   v         v
Normal    Suspicious
9,700        300
              |
              v
        Merchant reviews
```

FraudShield does the first pass. It doesn't replace the human decision — it decides **what deserves a human decision**. 300 cases is a day's work for one analyst. 10,000 is not work anyone does.

That framing also sets what the system is accountable for: **routing attention well**. Not being right about fraud in some absolute sense — being right about what's worth looking at.

---

## 7. Why this is an "AI Risk Manager" and not a fraud classifier

A system that outputs this is not useful:

```text
Transaction #83921: FRAUD
```

The analyst can't act on it. They can't check it. If it's wrong, nobody can tell why. And it's a claim the system has no standing to make — at the moment of payment, **nobody knows** whether it's fraud. That's only settled later, by an investigation or a chargeback.

A system that outputs this *is* useful:

```text
Transaction #83921    Risk 87/100    ->  SEND FOR REVIEW

Why:
  8 payment attempts in 10 minutes
  Device linked to 5 accounts
  Amount is 5.2x this customer's average
  First time using this payment method
  High recent failure rate on this account

Recommendation: manual review
Logged to audit trail
```

Same underlying model. Completely different tool. The analyst can verify each line, disagree with the conclusion, and leave a record either way.

So FraudShield outputs a **risk score and a recommendation**, never a verdict. `87` means "high risk, a human should look at this." It does not mean "this is fraud." Keeping that line clean is what makes the system defensible — to an analyst, to a merchant, and to a regulator asking why a customer was declined.

---

## 8. The four loss classes we handle

| Loss class | What it looks like | Where we catch it |
| --- | --- | --- |
| Stolen payment method | Unusual amount, new device, off-pattern timing | At checkout, before shipping |
| Card testing | Rapid small attempts, high failure rate | At checkout, within seconds |
| Coordinated abuse / rings | Many accounts sharing devices, IPs, cards | Entity graph, at signup and at checkout |
| Promotion abuse | Multiple accounts claiming one welcome offer | At redemption, using the same graph |

And one we're honest about **not** catching:

| Loss class | Why we miss it |
| --- | --- |
| First-party ("friendly") fraud | A real customer makes a real purchase, then falsely claims it never arrived. The transaction has no risk signal at all — it genuinely is a normal purchase. Catching this needs delivery evidence and claim history, not payment features. |

That last row matters. First-party abuse is one of the merchant's larger real losses and our transaction scorer recovers less than half of it. Pretending otherwise would be the easiest thing for a judge to take apart.

---

## 9. In one sentence

**The problem:** merchants lose money to fraudulent and abusive payment activity, but it's hard to stop because legitimate and fraudulent transactions often look identical at the moment of payment.

**FraudShield's job:** analyse payment behaviour, surface suspicious transactions and coordinated abuse, explain why each one is suspicious, and help the merchant act — without punishing genuine customers in the process.

---

## Where to go next

| Document | For |
| --- | --- |
| [README](../README.md) | What was built, tech stack, how to run it |
| [RISK_ENGINE.md](RISK_ENGINE.md) | How the scoring actually works |
| [EVALUATION.md](EVALUATION.md) | Whether it works — measured, with the false-positive cost in rupees |
| [ARCHITECTURE.md](ARCHITECTURE.md) | How the system is put together |
