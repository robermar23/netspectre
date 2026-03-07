---
description: Review test case coverage and implement missing tests to achieve 80% test code coverage
---
1. Run the test suite with coverage enabled to gather the baseline code coverage metrics.
// turbo
```powershell
npx vitest run --coverage
```

2. Analyze the coverage output to identify which files fall below the 80% coverage threshold. Focus especially on lines, functions, and branches that are untested.

3. For each file missing coverage, read its source code and corresponding test file to identify the logical paths (e.g., error handling, edge cases, specific `if/else` branches) without test cases.

4. Implement missing test cases in the test files to target the untested code. Ensure you:
   - Properly mock dependencies like `fs`, `child_process`, or `electron` if applicable.
   - Target the uncovered branches and error paths directly.
   - Keep tests isolated and maintainable.

5. Re-run the test suite with coverage to verify the improvements.
// turbo
```powershell
npx vitest run --coverage
```

6. Compare the new coverage metrics with the 80% target. Ensure all tests pass.
   - If the coverage is still below 80% or any tests fail, debug the failures or add more cases and repeat step 5.
   - If 80% coverage is achieved and all tests pass natively, you have completed the workflow.

7. Present a summary to the user outlining the tests added, the files modified, and the new total test coverage percentages.
