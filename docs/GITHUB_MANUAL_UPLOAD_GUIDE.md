# GitHub manual-upload guide

This repository is designed to be easy to update through GitHub's **Add file → Upload files** flow.

## Why there are no required hidden files

GitHub Actions, issue templates, and `.gitignore` require dot-path names such as `.github/workflows/qa.yml` and `.gitignore`. Those names are useful on GitHub, but they are inconvenient when manually uploading files from Finder or a browser because dotfiles may be hidden or skipped.

For that reason, the public evaluation manifest intentionally treats these files as **optional GitHub repository hygiene**, not required evidence for the IETF 126 public evaluation packet. The runnable public packet is the source files plus `ietf126/`.

## Required for public evaluation

The following command should pass without any `.github/` directory or `.gitignore` file:

```bash
python verify_manifest.py
python ietf126/run_review_packet.py
make qa
```

## Optional GitHub enhancements

Visible copies are provided under `github-ui-files/`:

```text
github-ui-files/gitignore.txt
github-ui-files/workflows/qa.yml
github-ui-files/workflows/ietf126-review-packet.yml
github-ui-files/issue-templates/ietf126-cross-reference.md
github-ui-files/issue-templates/ietf126-field-model.md
github-ui-files/issue-templates/ietf126-negative-vector.md
```

If you are using a local checkout, run:

```bash
python tools/materialize_github_files.py
```

That creates:

```text
.gitignore
.github/workflows/qa.yml
.github/workflows/ietf126-review-packet.yml
.github/ISSUE_TEMPLATE/ietf126-cross-reference.md
.github/ISSUE_TEMPLATE/ietf126-field-model.md
.github/ISSUE_TEMPLATE/ietf126-negative-vector.md
```

If you only use GitHub Web UI, use **Add file → Create new file** and type the target path exactly, then paste the corresponding visible template content.

## Public boundary

The hidden GitHub files do not change the public evaluation result, protocol posture, or licensing/IP boundary. They only enable GitHub Actions, issue-template convenience, and local ignore hygiene.
