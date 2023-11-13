SELECT file_change_id, diff
FROM file_change_cpp
LEFT JOIN fixes  ON fixes.hash = file_change_cpp.hash
WHERE fixes.cve_id = ?
