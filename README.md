# Portfolio Release Auditor

A local Python command-line tool that flags common release risks before source code is shared publicly. It reports filenames, relative paths, line numbers, and finding categories only. It never prints matched secrets, contact details, notebook outputs, or file contents.

## Checks

- Hard-coded credential patterns in bounded text files.
- Email and phone-like strings in source and documentation.
- Private-key markers in bounded `.pem` and `.key` files, common OpenSSH private-key filenames, local environment files, SQLite databases (`.db`, `.sqlite`, `.sqlite3`), and likely personal-data filenames.
- Armored OpenPGP private-key markers in bounded `.asc` files; opaque `.pgp` and `.gpg` containers require manual review.
- Large binaries, model weights, archives, and dataset-like directories.
- Jupyter notebooks (`.ipynb`) with saved outputs, local paths, or credential-like source.
- Unreadable, deeply nested, or malformed Jupyter notebook structures.
- Presence of a recognized license file.
- The supplied root is resolved before scanning. Symlinks inside that resolved tree are never followed; sensitive-file and sensitive-directory symlinks are blockers, while other symlinks and oversized text files are flagged for review.


## Run

Use Python 3.11 or newer. The runtime uses only the Python standard library.

From this directory, install the local package and run the scan:

```text
python -m pip install -e .
python -m portfolio_guard PATH_TO_PROJECT
```

Write a machine-readable report to a chosen file:

```text
python -m portfolio_guard PATH_TO_PROJECT --json-output audit-report.json
```

Exit code 1 means a blocker category was found. Exit code 0 means no blocker category was detected. Warnings still require human review.


