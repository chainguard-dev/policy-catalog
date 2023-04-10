# Contributing

We welcome policy additions and contributions to the Policy Catalog for use with Sigstore's Policy Controller or Chainguard Enforce.

To propose a policy addition, please first discuss the change you wish to make via an issue.

## Policy guidelines

Please note, policies in this repo require the use of the conventions outlined below.

This repo uses the following conventions to help collate similar CUE and Rego policies.

1. CUE policies should end with `-cue.yaml` and `metadata.name` should end with `-cue`
1. Rego policies should end with `-rego.yaml` and `metadata.name` should end with `-rego`

In order for the policies to be included in the Policy Catalog, they must the first three annotations in the list below. If any of these annotations are missing (with the expectiption of the `learnMoreLink`), then the policy will not be included in the Policy Catalog.

| Annotation | Description |
| --- | --- |
| `catalog.chainguard.dev/title` | Human-friendly name for the policy |
| `catalog.chainguard.dev/description` | Human-friendly description explaining the purpose of the policy |
| `catalog.chainguard.dev/labels` | Comma-separated list of labels |
| `catalog.chainguard.dev/learnMoreLink` | _Optional_. A link to more information about the policy. |

For more information about creating policies for the Policy Controller, please visit Sigstore's [Policy Controller Overview](https://docs.sigstore.dev/policy-controller/overview/).

## Pull Request Process

1. Create an issue outlining the fix or feature.
2. Fork the repository to your own GitHub account and clone it locally.
3. Hack on your changes. If you are adding a new policy file, make sure you add it to the the appropriate [policy subdirectory](policies). Give your file a name that succinctly describes the action of the policy.
4. Update the relevant README.md (such as within the policy directory) with details of changes to any interface.
5. Before making a PR, please make sure to run and pass a unit test.
6. Correctly format your commit message see [Commit Messages](#commit-message-guidelines) below.
7. Ensure that CI passes. If it fails, fix the failures.
8. Currently, every pull request requires a review from the Chainguard's Policy Catalog team before merging.
9. If your pull request consists of more than one commit, please squash your commits as described in [Squash Commits](#commit-message-guidelines)

## Commit Message Guidelines

We follow the commit formatting recommendations found on [Chris Beams' How to Write a Git Commit Message article](https://chris.beams.io/posts/git-commit/).

Well formed commit messages not only help reviewers understand the nature of
the Pull Request, but also assists the release process where commit messages
are used to generate release notes.

A good example of a commit message would be as follows:

```
Summarize changes in around 50 characters or less

More detailed explanatory text, if necessary. Wrap it to about 72
characters or so. In some contexts, the first line is treated as the
subject of the commit and the rest of the text as the body. The
blank line separating the summary from the body is critical (unless
you omit the body entirely); various tools like `log`, `shortlog`
and `rebase` can get confused if you run the two together.

Explain the problem that this commit is solving. Focus on why you
are making this change as opposed to how (the code explains that).
Are there side effects or other unintuitive consequences of this
change? Here's the place to explain them.

Further paragraphs come after blank lines.

 - Bullet points are okay, too

 - Typically a hyphen or asterisk is used for the bullet, preceded
   by a single space, with blank lines in between, but conventions
   vary here

If you use an issue tracker, put references to them at the bottom,
like this:

Resolves: #123
See also: #456, #789
```

Note the `Resolves #123` tag: this references the issue raised and allows us to
ensure issues are associated and closed when a pull request is merged.

Please refer to [the Github help page on linking issues](https://docs.github.com/en/issues/tracking-your-work-with-issues/linking-a-pull-request-to-an-issue) for more information and valid keywords.

## Squash Commits

Should your pull request consist of more than one commit (perhaps due to
a change being requested during the review cycle), please perform a git squash
once a reviewer has approved your pull request.

A squash can be performed as follows. Let's say you have the following commits:

    initial commit
    second commit
    final commit

Run the command below with the number set to the total commits you wish to
squash (in our case 3 commits):

    git rebase -i HEAD~3

You default text editor will then open up and you will see the following::

    pick eb36612 initial commit
    pick 9ac8968 second commit
    pick a760569 final commit

    # Rebase eb1429f..a760569 onto eb1429f (3 commands)

We want to rebase on top of our first commit, so we change the other two commits
to `squash`:

    pick eb36612 initial commit
    squash 9ac8968 second commit
    squash a760569 final commit

After this, should you wish to update your commit message to better summarise
all of your pull request, run:

    git commit --amend

You will then need to force push (assuming your initial commit(s) were posted
to github):

    git push origin your-branch --force

Alternatively, a core member can squash your commits within Github.

## Code of Conduct

Chainguard adheres to and enforces the [Contributor Covenant](https://www.contributor-covenant.org/version/2/0/code_of_conduct.html) Code of Conduct.

Please take a moment to read our [code of conduct](CONTRIBUTING.md) document.
