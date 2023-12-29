import re
from enum import Enum

class TA(Enum):
    SKIP_REST = 1
    COMMENT_ENTER = 2
    COMMENT_EXIT = 3

class Tokenizer:
    def __init__(self):
        self.re = re.compile('(#include|[A-Z]{2,}|[A-Za-z][a-z]+|[0-9.]+|0x[0-9a-zA-Z]+|//|/[*]|[*]/|<<=?|>>=?|[+][+]|--|-=|[#+*/&|%!=<>^]=|&&|[|][|]|->|[.]|::|\n|\s+|.)')

    def _preprocess_token(self, token:str):
        return None

    def tokenize(self, s:str):
        '''Roughly tokenize code.
        Will replace numers with 123 or 12.34 except for 0 and 1'''

        in_comment = False
        r = []

        for line_ind, ln in enumerate(s.split('\n')):
            sc = self.re.scanner(ln)
            char_ind = 0
            while (m := sc.match()) is not None:
                    char_ind += 1
                    token = m.group()
                    match self._preprocess_token(char_ind, token):
                        case TA.SKIP_REST:
                            break
                        case TA.COMMENT_ENTER:
                            in_comment = True
                        case TA.COMMENT_EXIT:
                            in_comment = False
                            continue
                        case None:
                            pass
                        case _:
                            raise ValueError('Invalid _preprocess_token result')

                    if not in_comment and not token.isspace() and token != '_':
                        if token == '0' or token == '1':
                            r.append((line_ind, token))
                        elif token.isdigit():
                            r.append((line_ind, '123'))
                        elif token.isdecimal():
                            r.append((line_ind, '12.34'))
                        else:
                            r.append((line_ind, token))

        return r

class CLikeTokenizer(Tokenizer):
    def __init__(self, include: str):
        super().__init__()
        self.include = include

    def _preprocess_token(self, ind, token:str):
        match ind, token:
            case _, '//':
                return TA.SKIP_REST
            case _, '/*':
                return TA.COMMENT_ENTER
            case _, '*/':
                return TA.COMMENT_EXIT
            case 1, self.include:
                return TA.SKIP_REST
            case _:
                return None

class PythonTokenizer(Tokenizer):
    def _preprocess_token(self, ind, token:str):
        match ind, token:
            case _, '#':
                return TA.SKIP_REST
            case 1, 'import':
                return TA.SKIP_REST
            case 1, 'from':
                return TA.SKIP_REST
            case _:
                return None

def get_tokenizer(lang):
    match lang:
        case 'C' | 'C++':
            return CLikeTokenizer('#inlude')
        case 'C#':
            return CLikeTokenizer('using')
        case 'Java':
            return CLikeTokenizer('import')
        case 'JavaScript':
            return CLikeTokenizer('import')
        case 'PHP':
            return CLikeTokenizer('use')
        case 'Python':
            return PythonTokenizer()
        case _:
            return Tokenizer()
