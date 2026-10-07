# phishing-email-analyzer

small python script that does a quick static triage of suspicious emails. give it a `.eml` file, it tells you what looks off and gives a rough risk score. no dependencies, fully offline, never opens any link.

built as a SOC analyst practice project, since checking a reported phishing email is one of the most common tier 1 tasks.

## what it checks

- **headers**: From vs Reply-To vs Return-Path domain mismatch, fake domain in the display name, received hop count
- **auth results**: SPF, DKIM, DMARC pass/fail from the headers
- **links**: IP as host, url shorteners, punycode lookalikes, suspicious TLDs, no HTTPS, `@` tricks, link text that shows one domain but points to another
- **attachments**: risky extensions (exe, js, docm, etc), double extensions like `invoice.pdf.exe`, sha256 hash for lookup on VirusTotal
- **wording**: common urgency / pressure phrases

urls are printed defanged (`hxxp://evil[.]com`) so you can't click them by accident.

## usage

```bash
python3 analyzer.py samples/sample_phish.eml
python3 analyzer.py mail1.eml mail2.eml
python3 analyzer.py mail.eml --json
```

needs python 3.8+, nothing to install.

## example output

```

=== samples/sample_phish.eml ===
  From            SecureBank Support <support@securebank.com>
  Reply-To        helpdesk@securebank-verify.xyz
  Return-Path     <bounce@sketchy-host.top>
  To              victim@example.org
  Subject         URGENT: Your account will be closed
  Date            Tue, 06 Oct 2026 08:13:55 +0000
  Message-ID      <abc123@sketchy-host.top>
  Received hops   1

  Auth: SPF=fail, DKIM=none, DMARC=fail

  Links (2):
    - hxxp://198[.]51[.]100[.]7/login/verify[.]php
        ! IP address as host
        ! no HTTPS
        ! link text shows www.securebank.com but goes to 198.51.100.7
    - hxxp://securebank-verify[.]xyz/confirm
        ! suspicious TLD .xyz
        ! no HTTPS

  Attachments (1):
    - invoice.pdf.exe (28 bytes)
      sha256 ccce76c220cf1cb46797be59d5410738af2cca89c2a285515c297b3a4960111a

  Findings:
    +15  Reply-To domain (securebank-verify.xyz) differs from From (securebank.com)
    +10  Return-Path domain (sketchy-host.top) differs from From (securebank.com)
    +20  SPF fail
    +20  DMARC fail
    +40  suspicious link traits (see links section)
    +15  urgency / pressure wording: verify your account, suspended, within 24 hours, action required, unusual activity
    +25  risky attachment type: invoice.pdf.exe
    +20  double extension: invoice.pdf.exe

  RISK: HIGH (score 100)
```

(the sample email is fake, made up for testing. domains and the "attachment" are harmless.)

## scoring

each finding adds points, capped at 100. under 20 is LOW, 20 to 49 is MEDIUM, 50+ is HIGH. the weights are my own rough picks, not a standard, so treat the score as a hint and not a verdict.

## limitations

- static only. no DNS lookups, no sandboxing, no reputation checks
- relies on the auth headers already in the email, doesn't re-verify SPF/DKIM itself
- keyword and TLD lists are short, easy to extend at the top of `analyzer.py`
- a clean score doesn't mean the email is safe

## ideas for later

- hash and domain lookup against VirusTotal / AbuseIPDB (could reuse my ioc lookup tool)
- parse `.msg` files too
- html report output

## license

MIT
