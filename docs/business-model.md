# Business model

Date: 2026-07-09

Status: pricing and revenue model are hypotheses to test after technical and maintainer validation.

## Open-source boundary

The local product should remain genuinely useful without a hosted subscription. The proposed open-source core includes:

- issue and exact-commit input;
- candidate test generation through documented provider adapters;
- local sandbox execution;
- deterministic `reproassert-report.json` output;
- patch and one-command reproduction output; and
- local verification and reruns.

Users provide their own model credentials and compute. Hosted value must come from operational work rather than withholding core correctness: managed isolated runners, private-repository GitHub integration, concurrency, retention, organization policy, and auditable team history.

## Buyer and pricing hypothesis

The likely buyer is an engineering manager, developer-experience/platform lead, or team lead responsible for bug-triage throughput and coding-agent quality. Per-attempt pricing is a better initial hypothesis than per-seat pricing because the workload is created by repositories and agents as well as humans.

Proposed paid experiment, not a published offer:

| Plan | Test price | Test allowance | Hypothesized value |
| --- | ---: | ---: | --- |
| Local open source | $0 | User-operated | Full local core, BYOK, local evidence |
| Hosted Team | $199 per team per month | 100 issue attempts | Private repositories, managed isolated runners, GitHub App, concurrency, report retention, policy controls |

Do not set overage pricing until aggregate failed-attempt and successful-attempt costs are measured. Run a paid pilot at $199 only after the technical benchmark and an independently useful maintainer result.

## Pricing anchors

Current adjacent list prices provide context, not proof of ReproAssert willingness to pay:

- [GitHub Copilot](https://github.com/features/copilot/plans) lists individual plans at $10, $39, and $100 per user per month and can assign issue work to coding agents.
- [CodeRabbit](https://docs.coderabbit.ai/management/plans) lists Pro+ at $48 per developer per month billed annually or $60 month-to-month and includes unit-test generation.
- [Qodo](https://www.qodo.ai/pricing/) lists a $30 Pro Team starting offer for its broader code-review platform.
- [LogicStar](https://logicstar.ai/pricing) lists its broader bug-ranking and autonomous-fix Starter product at $400 monthly or $320 monthly billed annually.

These products have broader or different workflows. Their prices bound an experiment; they do not justify ReproAssert's price by themselves.

## Exact path to $10,000 MRR

Base case:

```text
51 Hosted Team accounts x $199/month = $10,149 MRR
```

Acquisition sensitivity:

```text
At 10% qualified-trial-to-paid conversion: 510 qualified trials for 51 accounts
At  5% qualified-trial-to-paid conversion: 1,020 qualified trials for 51 accounts
```

Price sensitivity:

| Monthly account price | Accounts required | Resulting MRR |
| ---: | ---: | ---: |
| $99 | 102 | $10,098 |
| $199 | 51 | $10,149 |
| $399 | 26 | $10,374 |

This is customer math, not a forecast. No conversion, churn, retention, or willingness-to-pay rate has been measured.

## Cost and margin model

At the technical target of 30 successful reproductions per 100 attempts, the following is only an illustrative scenario:

```text
Revenue                              $199
Illustrative total variable cost      30
Illustrative contribution            $169 (84.9%)
```

The $30 input is not established by a median cost-below-$1 gate. Gross-margin accounting must include model calls and compute for failed attempts, dependency preparation, runner idle time, storage, retries, abuse, and support. No margin claim is permitted until total variable cost across all attempts is measured.

## What must be proven before scaling

1. The technical and maintainer gates in [market-validation.md](market-validation.md) pass.
2. A qualified team completes at least three real issue attempts and asks to continue.
3. At least one team pays the proposed $199 price; a letter of intent or favorable interview is insufficient.
4. Aggregate variable cost supports a credible contribution margin.
5. Private-repository security, secrets isolation, retention, deletion, and incident-response behavior are documented and tested.
6. Repeat usage is caused by ongoing issue volume rather than one demonstration.

Verdict: maintain the free local core and test one simple team plan. Do not build a broad dashboard, enterprise sales surface, or billing system before technical usefulness and repeat demand are demonstrated.
