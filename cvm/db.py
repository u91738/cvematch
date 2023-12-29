import sqlite3
import os.path
from pathlib import Path
from dataclasses import dataclass
from typing import List

def read_file(fname):
    with open(Path(__file__).parent / fname, 'r') as f:
        return f.read()

@dataclass
class Cwe:
    cwe_id: str
    cwe_name: str
    description: str

@dataclass
class CveReport:
    cve_id: str
    description: str
    diff: str
    cwe: List[Cwe]

class Database:
    def __init__(self, fname):
        self.fname = fname
        self.cve_get_changes_sql = read_file('sql/cve_get_changes.sql')
        self.cve_all_get_changes_sql = read_file('sql/cve_all_get_changes.sql')
        self.cve_list_sql = read_file('sql/cve_list.sql')
        self.cwe_list_sql = read_file('sql/cwe_list.sql')
        self.cve_report_sql = read_file('sql/cve_report.sql')
        self.cwe_get_cves = read_file('sql/cwe_get_cves.sql')
        self.all_code_sql = read_file('sql/code_all.sql')
        self.cve_report_cwe_sql = read_file('sql/cve_report_cwe.sql')

    def __enter__(self):
        self.__db = sqlite3.connect(self.fname)
        return self

    def __exit__(self ,type, value, traceback):
        self.__db.close()

    def __select(self, sql, *args):
        c = self.__db.cursor()
        c.execute(sql, args)
        res = []
        while f := c.fetchone():
            res.append(f[0] if len(f) == 1 else f)
        return res

    def get_cves_by_cwe(self, cwe_id):
        return self.__select(self.cwe_get_cves, cwe_id)

    def get_cve(self, cve_id):
        return self.__select(self.cve_get_changes_sql, cve_id)

    def get_cves(self, lang):
        r = self.__select(self.cve_all_get_changes_sql, lang)
        if lang == 'C++':
            r += self.__select(self.cve_all_get_changes_sql, 'C')
        return r

    def list_cves(self):
        return self.__select(self.cve_list_sql)

    def list_cwes(self):
        return self.__select(self.cwe_list_sql)

    def cve_report(self, file_change_id):
        for (cve_id, description, diff) in self.__select(self.cve_report_sql, file_change_id):
            cwes = self.__select(self.cve_report_cwe_sql, cve_id)
            yield CveReport(cve_id, description, diff, [Cwe(*i) for i in cwes])

    def all_code(self, lang):
        r = self.__select(self.all_code_sql, lang, lang)
        if lang == 'C++':
            r += self.__select(self.all_code_sql, 'C', 'C')
        return r
