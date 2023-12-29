SELECT programming_language, count(*)
FROM file_change
GROUP BY programming_language
