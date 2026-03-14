/** @type {import('@commitlint/types').UserConfig} */
// Enforces Conventional Commits across all PRs
module.exports = {
  extends: ["@commitlint/config-conventional"],
  rules: {
    "type-enum": [
      2,
      "always",
      [
        "feat",
        "fix",
        "chore",
        "docs",
        "test",
        "refactor",
        "perf",
        "ci",
        "build",
        "style",
        "revert",
      ],
    ],
    "subject-empty": [2, "never"],
    "type-empty": [2, "never"],
    "subject-case": [0],
  },
};
