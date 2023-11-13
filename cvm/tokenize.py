import re

tokenizer = re.compile('([A-Z]{2,}|[A-Za-z][a-z]+|[0-9.]+|0x[0-9a-zA-Z]+|<<=?|>>=?|[+][+]|--|-=|[+*/&|%!=<>^]=|&&|[|][|]|->|[.]|::|\n|\s+|//[^\n]+\n|/[*]|[*]/|.)')

def tokenize(s, replace_numbers=True, get_line=False):
    '''Roughly tokenize C++ code.
       replace_numbers will replace numers with 123 or 12.34 except for 0 and 1.
       get_line - return line numbers instead of tokens'''
    sc = tokenizer.scanner(s)
    in_comment = False
    r = []
    line = 1

    if get_line:
        def get_token(line, _):
            return line
    else:
        def get_token(_, token):
            return token

    while (m := sc.match()) is not None:
        token = m.group()
        if token == '\n' or token.startswith('//'):
            line += 1

        if not token.isspace() and token != '_' and not token.startswith('//'):
            if token == '/*':
                in_comment = True
            elif token == '*/':
                in_comment = False
            elif not in_comment:
                if token == '0' or token == '1':
                    r.append(get_token(line, token))
                elif replace_numbers and token.isdigit():
                    r.append(get_token(line, '123'))
                elif replace_numbers and token.isdecimal():
                    r.append(get_token(line, '12.34'))
                else:
                    r.append(get_token(line, token))
    return r
