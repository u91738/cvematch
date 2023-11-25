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
        self.cve_report_cwe_sql = read_file('sql/cve_report_cwe.sql')
        self.all_code_sql = read_file('sql/code_all.sql')

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
            res.append(f)
        return res

    def get_cve(self, cve_id):
        return self.__select(self.cve_get_changes_sql, cve_id)

    def get_cves(self):
        return self.__select(self.cve_all_get_changes_sql)

    def list_cves(self):
        return self.__select(self.cve_list_sql)

    def list_cwes(self):
        return self.__select(self.cwe_list_sql)

    def cve_report(self, file_change_id):
        [(cve_id, description, diff)] = self.__select(self.cve_report_sql, file_change_id)
        cwes = self.__select(self.cve_report_cwe_sql, cve_id)
        return CveReport(cve_id, description, diff, [Cwe(*i) for i in cwes])

    def all_code(self):
        return self.__select(self.all_code_sql)
