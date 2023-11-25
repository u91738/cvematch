# cvematch
Fuzzy search for code similar to code that caused known vulnerabilities.
Reports should be interpreted as "structure of this code loosely reminds the code that lead to CVE-123".
Its purpose is to suggest candidates for manual code audit, somewhat like you would use a noisy static analyzer, not an SCA tool.
C and C++ only, at least for now.

Uses OpenCL for computation-intensive parts, you may want a machine with GPU.

## Usage

To prepare the dataset, change to the cvematch directory and run `./setup.sh` then `./cleanup.sh`.

```
$ ./cvematch.py --help
usage: ./cvematch.py --report-diff --cve='CVE-1999-0199' --max-score 0.3 some/project/src/*.c

Match known CVE fixes to your code. The result should be interpreted as "structure of this code
loosely reminds the code that lead to CVE-123"

positional arguments:
  files                 Source files to check

options:
  -h, --help            show this help message and exit
  --db DB               Path to database
  --cve CVE             CVE id to check. Can be repeated.
  --cwe CWE             Check all CVEs with this CWE id. Can be repeated.
  --no-cve NO_CVE       CVE id to not check. Can be repeated.
  --w2v-show            show distances to some word2vec tokens
  --w2v-list            list available word2vec files
  --w2v W2V             word2vec files name to use, see --w2v-list
  --cve-list            show list of available CVEs
  --cwe-list            show list of available CWEs
  --report-cve-info     show CVE description for matches
  --report-cwe          show CWE id and description for matches
  --report-diff         on match show diff for matching hunk in CVE fix
  --report-diff-full    on match show full diff of CVE fix
  --max-score MAX_SCORE
                        Max score value that is considered low enough to show as a result. Reasonable
                        values are from 0.05 (~exact copy of CVE) to 0.3 (loosely reminds of some
                        CVE)
```

## How it works

Uses [CVEFixes](https://zenodo.org/records/7029359) dataset as a source of diffs for public vulnerabilities.

Each source file is scored as follows:
- Search source for a substring with minimal Levenstein distance* to each hunk in diff for a CVE fix.
- If distance for diff part before change is less than certain threshold, compute (1) for CVE's diff code after fix.
- If distance to code before fix is less than distance after fix, report the issue.

*Levenstein distance here is not the usual string matching case.
The insert-delete-substitute operations are done on whole words / tokens.
Substitution cost is cosine distance between word2vec vectors, which lets it decide that substitution of "a_size" with "a_len" is semantically closer than "a_size" -> "a_index" ("a", and, "size" will be separate tokens).
