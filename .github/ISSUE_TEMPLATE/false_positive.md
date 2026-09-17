---
name: False positive
about: The scanner flagged something it shouldn't have
labels: false-positive
---

**File / pattern flagged**

**Command used**
```bash
repo-scanner <args here>
```

**Why it's a false positive**

**Have you tried `.reposecurityignore`?**

A `.reposecurityignore` file in the scanned repo's root can suppress known false positives (see README section 2.4). If it doesn't cover this case, say why below.

**Suggested fix**
(e.g. tighten a regex, add an entropy/length filter, exclude a file type)
