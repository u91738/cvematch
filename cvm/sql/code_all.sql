SELECT code_before as code
FROM file_change
WHERE programming_language = ?
UNION
SELECT code_after
FROM file_change
WHERE programming_language = ?
