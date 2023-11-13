SELECT code_before as code
FROM file_change_cpp
UNION
SELECT code_after
FROM file_change_cpp
