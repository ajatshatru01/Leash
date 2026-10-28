# Meta Global AI Developer Hackathon information

Last checked: October 28, 2026  
Project: Leash  
Track: Indie Developer  
Recommended problem statement: **Push the Frontier**

## Purpose of this document

This file is the repository's working source of truth for hackathon requirements and judging strategy. It combines:

1. the participant guide supplied directly to the project owner;
2. the Hackathon Terms & Conditions (“Official Rules”) and Event Waiver dated October 25, 2026, supplied directly to the project owner;
3. public event information from the [Meta Global AI Developer Hackathon event page](https://cerebralvalley.ai/e/meta-ai-developer-hackathon);
4. project-specific implications for Leash.

If this file conflicts with the accepted Official Rules, submission portal, organizer email, or a later organizer announcement, those sources take precedence. Record any changes here immediately.

This document is a project-planning summary, not legal or tax advice. Read the accepted Official Rules themselves before submitting.

## Event summary

- Hosts: Meta and Cerebral Valley.
- Format: virtual only, worldwide for eligible selected participants.
- Build period: October 26 through November 4, 2026.
- Submission deadline: **November 4, 2026 at 9:00 PM Eastern Time**.
- India conversion: **November 5, 2026 at 7:30 AM IST**, based on the event page's stated 9:00 PM EST deadline. Reconfirm this in the submission portal before relying on it.
- Submission portal: [Cerebral Valley hackathon submission page](https://cerebralvalley.ai/e/meta-ai-developer-hackathon/hackathon/submit).
- Judging: November 4–8, 2026.
- Closing ceremony and winners: November 9, 2026.
- Total announced prize pool: $1,000,000 across the Indie Developer and Startup tracks.
- Participant Meta Model API credit: **$150**, subject to separate Credit Terms and valid for the ten-day development window.

The public event page also lists optional partner support for selected participants. These offers are separate from the guaranteed $150 Meta Model API credit and should not be assumed available:

- Baseten: $100 in credits and 2M TPM rate limits for selected participants;
- Modal: $100 in credits for selected participants;
- Fireworks: $100 in credits for selected participants.

## Track, team, and eligibility requirements

- A participant may apply to only one track, and a project may be submitted to only one track.
- Leash is entered in the **Indie Developer track**.
- The Indie track permits individual builders, students, and teams of up to four eligible people.
- If a team is used, one eligible Representative must submit the project, identify every team member, be authorized to act for the team, and confirm that all members accepted the Official Rules.
- Leash is currently a solo project, so the participant is also the submitter and prize recipient unless the team changes before submission.
- Participants must be at least 18 and have reached the age of majority in their jurisdiction.
- Participants must not be in a prohibited jurisdiction or subject to applicable sanctions/export restrictions.
- Meta or Cerebral Valley employees, contractors, interns, government-affiliated individuals, specified immediate family/household members, and other excluded parties described in the Official Rules are ineligible.
- Application and submission information must be complete and truthful. Eligibility is re-verified before any prize is awarded.

### One-track rule for Leash

Do not submit Leash, a renamed fork, or a substantially identical version to both tracks. Keep all repository, video, portal, and pitch language consistent with the Indie Developer track.

## Prize structure and payout

### Indie Developer track — $400,000 total

| Place | Prize |
|---:|---:|
| 1st | $150,000 |
| 2nd | $100,000 |
| 3rd | $75,000 |
| 4th | $50,000 |
| 5th | $25,000 |

### Other prizes

- Startup track: $550,000 total across five places.
- Bonus awards: up to $50,000 in aggregate for categories the organizers may define, potentially including community vote, most viral, or other standout-project awards.
- Bonus prizes are expected to be announced on or about November 10, 2026 and do not reduce track prizes.

### Winner verification and payment

- Judges' finalist selections are final and binding, subject to organizer verification.
- A potential winner is not a winner until eligibility and rule compliance are verified.
- Cerebral Valley administers payout after verification and receipt of required documents and funds from Meta.
- Payment is expected within 30 days after verification and receipt of required documentation.
- U.S. winners may need a W-9; non-U.S. winners may need a W-8BEN and local banking/tax documentation.
- Winners are responsible for taxes, bank/wire charges, foreign-exchange costs, and local reporting or banking compliance.
- A team prize may be paid to the Representative or split according to written team instructions. Organizers do not resolve allocation disputes.

Prize money should not influence technical claims or risk-taking in the demo. Build and demonstrate only inert attacks against disposable fixtures.

## Required problem statement

Every project must build toward one of these problem statements.

### Build for Your World

Bring Meta's models into a domain the builder knows firsthand. Solve a meaningful problem, free up time or mental space, and make something possible that was not possible before.

### Push the Frontier

Use Meta's models in software, robotics, manufacturing, energy, materials, or another technical domain. Give a machine a new capability, accelerate an experiment, or improve how people understand and control a physical or software system.

### Leash positioning

Use **Push the Frontier** as Leash's primary problem statement:

> Leash gives autonomous coding agents a new capability: the ability to delegate high-impact machine actions through a local, task-aware safety boundary that can preview, veto, and audit those actions before execution.

The project also has a credible Build for Your World story—independent developers need a practical safety net when using autonomous coding agents—but the submission should select and consistently lead with one statement. Push the Frontier better emphasizes the novel technical capability and avoids presenting Leash as a generic developer utility.

## Meta model and tooling requirement

Stage One requires a reasonable fit with a problem statement and reasonable use of the Meta Model API and/or Meta open-weight models. A superficial or optional integration risks immediate elimination.

Available Meta tooling named in the participant guide includes:

- Muse Spark series through Meta Model API;
- Muse Wonder through Meta Model API;
- Muse Image through Meta Model API;
- Muse Voice Transcribe through Meta Model API;
- SAM 3.1 through Meta Model API;
- Muse Glimmer as an open-weight local model;
- Muse Spark Open as an open-weight model;
- Muse Code as a coding agent.

### Leash's essential Meta integration

Leash should make two Meta models visibly indispensable:

1. **Muse Spark is the actor.** It receives the user's coding task, reasons about the repository, and proposes structured tool actions.
2. **Muse Wonder is the semantic counterparty.** A separate stateless Wonder request judges ambiguous proposals against the original task and a minimal, locally redacted impact preview.

The opposing roles are the core creative use of Meta tooling: Muse Spark proposes actions while Muse Wonder independently evaluates sanitized intent and impact. Raw secrets and full file contents are removed locally before the managed request.

Muse Code may be used to help build the project, but development assistance is not a substitute for Meta models being central to the submitted product. Do not add Muse Image, SAM, Voice Transcribe, or Wonder merely to increase the model count; unnecessary integrations weaken the product story.

## Sample anti-projects

The participant guide warns against generic, overused, or policy-sensitive project categories. Avoid submitting:

- AI-generated medical advice, including mental-health advisors and skin-blemish detectors;
- basic retrieval-augmented generation applications;
- simple image analyzers;
- simple AI-for-education chatbots;
- AI job-application screeners;
- AI nutrition coaches;
- personality analyzers;
- sports analyzers or coaches;
- political or war-related projects.

Leash does not fall into these categories. Its risk is different: it could still appear generic if reduced to “an LLM classifies commands as safe or unsafe.” The enforceable capability boundary, resolved impact preview, local/private judgment, hybrid benchmark, and live agent retry are what distinguish it from an anti-project-quality wrapper.

## Submission ownership, licensing, and confidentiality

These terms materially affect what may be placed in the repository, portal, demo, workshops, chat, and screen shares.

### What the participant keeps

As between the entrant and organizers, the entrant retains ownership of intellectual and industrial property rights in the submission.

### License granted to organizers

Submitting grants the organizers and their subsidiaries, agents, and partners a **perpetual, irrevocable, worldwide, royalty-free, non-exclusive license** to use, reproduce, adapt, modify, publish, distribute, publicly perform/display, create derivative works from, and otherwise exploit the submission without restriction, including for marketing and live demonstrations.

Materials shared more broadly during the event are not accepted under confidentiality, non-use, or non-disclosure obligations. The waiver also contains broad rights covering event materials, recordings, screen shares, chat messages, name, image, voice, likeness, and submission content.

### Submission warranties

By submitting, the participant represents that the submission:

- is the participant's or team's original work product;
- is solely owned by the participant/team/organization as represented;
- does not violate another party's copyright, trademark, patent, contract, privacy, or other proprietary rights.

Third-party technical assistance is permitted only when the submitted components remain the participant's own work and the participant owns all necessary rights. Open-source software or hardware may be used when its license is followed and the submission meaningfully enhances or builds upon it.

### Required repository hygiene

- Keep a dependency and asset inventory with names, versions, licenses, source links, and modifications.
- Include all required copyright notices and license texts.
- Do not copy proprietary code, benchmark datasets, logos, screenshots, audio, video, or generated assets without the necessary rights.
- Do not expose employer/client code, confidential security findings, personal data, or real credentials anywhere in the project or event channels.
- Use fake secrets, synthetic fixtures, local endpoints, and an original Leash logo/demo design.
- Keep evidence of authorship and hackathon-period work through Git history, dated benchmark artifacts, and build notes.
- Check the terms of every model, runtime, package, dataset, icon, font, and video/audio asset used in the final submission.

Because the organizers accept no confidentiality obligation, assume anything shown in the portal, repository, Discord, workshop, pitch, screen share, or recording may become public and reusable under the event terms.

## Judging process

The supplied participant guide states that judging has three stages, but it defines only the first two. The Official Rules confirm that organizer-selected judges choose finalists and that their selections are final and binding, but still do not describe the mechanics of Stage Three. Do not invent them; ask the organizers or check the submission portal/Discord.

### Stage One: pass/fail viability gate

A submission must:

- reasonably fit one of the two problem statements; and
- reasonably use Meta Model API and/or Meta open-weight models in the project built during the hackathon.

For Leash, the Stage One proof should be unmistakable within the first 15 seconds of the video and the first paragraph of the submission:

- label the project as Push the Frontier;
- show Muse Spark proposing an action;
- show Meta-hosted Muse Wonder evaluating a locally redacted judgment packet in an independent context;
- state that both are operating inside the working Leash pipeline.

### Stage Two: weighted 0–10 scoring

All projects that pass Stage One are scored from 0 to 10 in four categories.

| Category | Weight | What judges assess | What Leash must prove |
|---|---:|---|---|
| Impact | 30% | Real-world potential, beneficiaries, importance, likelihood of use, and fit with a problem statement | Autonomous coding agents are gaining dangerous machine authority; Leash keeps execution control, raw secrets, and full private content behind a local enforcement boundary |
| Use of Meta AI Tooling | 25% | Creative, non-basic use of Meta tools and surprising capabilities | Spark and Wonder play necessary opposing roles; Wonder uses the task plus resolved local impact to catch behavior that deterministic rules miss |
| Technical Depth & Execution | 20% | Sound engineering, refinement, and visible craft | The gateway owns capabilities, approval is bound to exact action/preview digests, failures close safely, egress is inspected, logs are redacted, and benchmarks are reproducible |
| Demo | 25% | A working and impressive live product plus a genuinely engaging video | A normal task flows silently, poisoned context triggers blocked exfiltration, indirect destruction shows concrete impact, and benchmark evidence appears in about 90 seconds |

Weighted score calculation:

```text
final_score =
    impact_score * 0.30
  + meta_tooling_score * 0.25
  + technical_score * 0.20
  + demo_score * 0.25
```

### Stage Three: unresolved

Neither the participant guide excerpt nor the Official Rules describe Stage Three mechanics. Before submission, determine:

- whether it is a live final, organizer review, public vote, or another pass;
- whether finalists need a live deployment or only the submitted demo;
- pitch and question-and-answer duration;
- whether new work may be added after the submission deadline;
- whether finalists must reproduce every external model/service call live.

## Rubric-driven strategy for Leash

### Impact — 30%

Lead with one user and one costly fear: an independent developer wants the speed of auto-approved coding agents without granting an untrusted cloud reasoning loop unrestricted access to secrets, files, git remotes, and the network.

Evidence to prepare:

- a clear before/after workflow;
- a concrete statement of who benefits;
- zero-byte proof from the local exfiltration endpoint;
- low false-block rate on normal coding actions;
- a credible path from the hackathon harness to integrations with other agent tools.

Avoid vague claims such as “AI safety for everyone” or unsupported market-size numbers.

### Use of Meta AI Tooling — 25%

Make the model pairing legible in the architecture and video:

```text
Muse Spark: capable cloud actor
        ↓ proposes action
Leash: rules + resolved impact + policy
        ↓ ambiguous cases
Muse Wonder on Meta Model API: sanitized semantic judge
        ↓ verdict
Leash executor: allow, review, or block
```

The surprising capability is not that Wonder labels a command. It is that one Meta model independently evaluates whether another Meta model's planned real-world action serves the user's intent, after Leash has resolved the real impact and removed raw secrets locally.

Capture the exact Meta model names, versions, serving runtime, quantization, prompts, structured-output schema, latency, and fallback behavior in the repository.

### Technical Depth & Execution — 20%

The minimum credible technical proof is:

- Spark has proposal tools but no unrestricted execution tool;
- the capability-limited executor is reachable only after authorization;
- deterministic hard blocks cannot be downgraded by Muse Wonder;
- malformed or unavailable model output fails to review/block, never allow;
- the preview and approval are cryptographically bound to the executed action;
- outbound fake secrets are detected and redacted before UI/model/audit exposure;
- LeashBench compares rules-only, Wonder-only, and hybrid configurations on frozen cases;
- benchmark artifacts include per-category results, false-block rate, and p50/p95 latency.

Do not claim universal shell interpretation, perfect prompt-injection detection, perfect secret detection, or kernel-level protection.

### Demo — 25%

Recommended 90-second sequence:

1. **0–10 seconds:** state the problem and one-line solution.
2. **10–25 seconds:** Spark fixes a failing test; safe actions pass silently.
3. **25–48 seconds:** a poisoned README causes a fake `.env` upload proposal; Leash blocks it and the local endpoint shows zero bytes received.
4. **48–68 seconds:** an encoded or nested destructive proposal is decoded or conservatively blocked; show the exact generated files and bytes at risk.
5. **68–82 seconds:** show the redacted, replayable audit record and Spark choosing a safer alternative.
6. **82–90 seconds:** show one LeashBench comparison chart and close with the Spark/Wonder pairing.

The demo must be real, deterministic, and safe. Use fake credentials, fixture files, a disposable workspace, and a local capture endpoint. Pre-warm both Meta models and record a backup video.

## Legal and operational risk notes

The Official Rules include broad releases, indemnification obligations, publicity/recording permissions, limitations on remedies, California governing law, and exclusive San Francisco venue. Participation also places the operational risks of connectivity, hardware/software failure, data loss, privacy/security incidents, and third-party services on the participant.

Practical consequences for Leash:

- keep encrypted local and off-device backups of source, benchmark results, video, and submission text;
- do not make the demo depend on one external inference provider or live network path;
- never show material that cannot safely become public;
- use a dedicated hackathon API key and rotate/revoke it after the event;
- verify recordings and screenshots for secrets, personal notifications, unrelated repositories, and identifying data;
- review the actual waiver and obtain professional advice if any IP, employment, tax, or liability term is unclear or consequential.

The organizers may modify the terms and communicate significant changes to registered participants. Recheck organizer email, Discord, portal, and event pages before submission.

## Submission gate checklist

### Eligibility and compliance

- [ ] Indie Developer track is selected consistently.
- [ ] The participant is eligible under the age, location, sanctions, employment, and household restrictions.
- [ ] Push the Frontier is selected and named consistently.
- [ ] The accepted Official Rules have been reviewed.
- [ ] Any team member is named, eligible, and has accepted the rules; one Representative is authorized.
- [ ] All submission fields and asset requirements are known.
- [ ] Stage Three has been clarified.
- [ ] All work claimed as hackathon work complies with the event rules.
- [ ] All dependencies, assets, datasets, models, and runtimes have an audited license/provenance entry.
- [ ] The submission contains only original work, properly licensed open source, or material for which the participant owns the necessary rights.
- [ ] No employer, client, teammate, or third-party confidential material appears anywhere in the submission or demo.
- [ ] No real credentials, private repositories, or unsafe attack payloads appear in the submission.

### Stage One

- [ ] The working product visibly uses Muse Spark.
- [ ] The working product visibly uses Muse Spark and Muse Wonder through Meta Model API, with both exact model identifiers disclosed.
- [ ] Meta integration is essential rather than decorative.
- [ ] The submission explicitly explains the Push the Frontier fit.

### Stage Two evidence

- [ ] Impact: the target user, pain, benefit, and adoption path are concrete.
- [ ] Meta tooling: model roles, versions, and unique pairing are documented.
- [ ] Technical depth: the capability boundary is enforced and demonstrated.
- [ ] Technical depth: LeashBench results are reproducible and honest.
- [ ] Demo: the live path works repeatedly on the exact presentation hardware.
- [ ] Demo: the video is concise, readable, and visually clear without narration-dependent details.
- [ ] Failure cases and limitations are disclosed.

### Final operational checks

- [ ] Submission is uploaded well before the deadline.
- [ ] The portal submission is made under the correct track and participant identity.
- [ ] Repository link and permissions work in a logged-out browser.
- [ ] Video link and playback permissions work in a logged-out browser.
- [ ] Setup instructions succeed from a clean checkout.
- [ ] Meta Model API account, model identifiers, credit use, latency, timeout, and fallback requirements are stated accurately.
- [ ] A backup recording and recorded proposal sequence are available.
- [ ] Source, results, submission copy, and video have redundant backups.
- [ ] API keys used during the hackathon are scoped, budget-limited where possible, and scheduled for rotation.
- [ ] Screen recordings contain no notifications, credentials, personal information, or unrelated confidential files.
- [ ] No public-network dependency is required for the attack proof.

## Official and technical links

- [Hackathon event page](https://cerebralvalley.ai/e/meta-ai-developer-hackathon)
- [Project submission portal](https://cerebralvalley.ai/e/meta-ai-developer-hackathon/hackathon/submit)
- [Muse Spark series](https://dev.meta.ai/models/muse-spark)
- [Muse Wonder](https://dev.meta.ai/models/muse-wonder)
- [Muse Image](https://dev.meta.ai/models/muse-image)
- [Muse Voice Transcribe](https://dev.meta.ai/models/muse-voice-transcribe)
- [SAM 3.1](https://dev.meta.ai/models/sam-3-1)
- [Meta Model API](https://dev.meta.ai/products/meta-model-api)
- [Muse Glimmer](https://dev.meta.ai/models/muse-glimmer)
- [Muse Spark Open](https://dev.meta.ai/models/muse-spark-open)
- [Muse Code](https://dev.meta.ai/lp/muse-code)

## Open organizer questions

Keep this list current and record answers with their source and date.

1. What exactly is Stage Three?
2. What files, links, video length, and repository visibility are required at submission?
3. Must the demo be publicly deployed, or is a local working demonstration acceptable?
4. Beyond the originality and ownership warranties, what restrictions apply to code, datasets, benchmark cases, or scaffolding created before October 26?
5. Are participants required to disclose all non-Meta models, coding assistants, or third-party technical assistance used?
6. Will finalists demonstrate live, and what hardware/network environment will be available?
7. Is the stated 9:00 PM deadline fixed to EST or intended as prevailing Eastern Time?
8. What exact license/credit terms govern the $150 API credit, including expiration and overage behavior?
