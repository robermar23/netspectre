---
description: Generate a commit message from staged git changes
---

1. Run `git diff --cached` to see all staged changes.
2. Analyze the diff to understand the nature of the changes (e.g., bug fixes, new features, refactoring).
3. Generate a concise and descriptive commit message. 
   - Follow the conventional commits format: `<type>(<scope>): <description>`
   - Types: feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert
   - Keep the first line under 50 characters if possible.
   - Provide a more detailed body if the changes are complex.
   - When referencing files, use only the basename (e.g., `scanner.js` not `src/main/scanner.js`)
4. Provide the generated commit message to the user for review.