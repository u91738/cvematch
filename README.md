# cvematch
Fuzzy search for code similar to code that caused known vulnerabilities.
Reports should be interpreted as "structure of this code loosely reminds the code that lead to CVE-123".
Its purpose is to suggest candidates for manual code audit, somewhat like you would use a noisy static analyzer, not an SCA tool.

Supported languages are C, C++, C#, Java, Python, PHP, JavaScript.
Should work with any other languages in dataset using a generic default tokenizer, not very useful for languages with less CVEs in dataset.

Uses OpenCL for computation-intensive parts, you may want a machine with a mid-range GPU.

## Usage

To prepare the dataset, change to the cvematch directory and run `./setup.sh` then `./cleanup.sh`.

```
$ ./cvematch.py --help
usage: ./cvematch.py --report-cve-info --report-cwe --report-diff --cve='CVE-1999-0199' some/project/src/*.c

Match known CVE fixes to your code. The result should be interpreted as "structure of this code
loosely reminds the code that lead to CVE-123"

positional arguments:
  files                 Source files to check

options:
  -h, --help            show this help message and exit
  --lang {C,C++,C#,Java,Python,PHP,JavaScript,Batchfile,CoffeeScript,Erlang,Go,HTML,Haskell,Lua,Matlab,Objective-C,Perl,PowerShell,R,Ruby,Rust,SQL,Scala,Shell,Swift,TypeScript}
                        programming language, case-sensitive
  --cve CVE             CVE id to check. Can be repeated.
  --cwe CWE             Check all CVEs with this CWE id. Can be repeated.
  --w2v-show            show distances to some word2vec tokens
  --w2v-list            list available word2vec files
  --w2v W2V             word2vec file name to use, see --w2v-list
  --cve-list            show list of available CVEs
  --cwe-list            show list of available CWEs
  --report-cve-info     show CVE description for matches
  --report-cwe          show CWE id and description for matches
  --report-diff         on match, show diff for matching hunk in CVE fix
  --report-diff-full    on match, show full diff of CVE fix
  --report-diff-id      on match, show internal id of matched diff to be used in --ignore
  --ignore IGNORE       CVE id, CWE id or diff id to ignore. See --cve-list, --cwe-list, --report-
                        diff-id
  --ignore-file IGNORE_FILE
                        file with --ignore args separated by new line
  --split-diffs         treat each hunk of file change as separate file diff
  --max-file-len MAX_FILE_LEN
                        set file length in tokens before it gets split into several pseudofiles. Use
                        it to fix out of memory
  --min-hunk-tokens MIN_HUNK_TOKENS
                        minimal token count for change to matter
  --max-score MAX_SCORE
                        Max score value that is considered low enough to show as a result.
                        Reasonable values are from 0.05 (~exact copy of CVE) to 0.3 (loosely reminds
                        of some CVE)
```

## Output example

This call to cvematch looks for CVE-1999-0199 in examples/88393274694273.c.
When close enough match is found, it shows CVE description, related CWE and diff from CVE fix that matched at line 164.
Score 0.266196 - 0.496774 means that found code has 0.266196 distance to original code in patch before CVE fix and 0.496774 to code after CVE fix.
Where 0 is perfect match and 1 - completely different.
0.000000 - 0.496774 is score for a specific hunk of a bigger patch in this specific place.

```
$ ./cvematch.py --lang C++ --report-cve-info --report-cwe --report-diff --cve='CVE-1999-0199' examples/88393274694273.c
Will check:
CVE-1999-0199
4 file diffs in cves
1 files, max tokens in file:  16384
Processing examples/88393274694273.c tokens: 16384
Matched CVE-1999-0199 with score 0.266196 - 0.496774
CVE Info: "manual/search.texi in the GNU C Library (aka glibc) before 2.2 lacks
a statement about the unspecified tdelete return value upon deletion of a tree's
root, which might allow attackers to access a dangling pointer in an application
whose developer was unaware of a documentation update from 1999."
CWE-252 - Unchecked Return Value
examples/88393274694273.c:164:0    0.000000 - 0.496774

#  define SWITCH_ENUM_CAST(x) (x)
# endif

-/* How many characters in the character set.  */
-# define CHAR_SET_SIZE 256
-
-# ifdef SYNTAX_TABLE
-
-extern char *re_syntax_table;
-
-# else /* not SYNTAX_TABLE */
-
-static char re_syntax_table[CHAR_SET_SIZE];
-
-static void
-init_syntax_once ()
-{

// ... rest of long patch that matched at this offset in file
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
