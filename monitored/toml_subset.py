"""Python 3.10 fallback for the deployed declaration/config TOML subset.

Python 3.11+ uses tomllib. Unsupported syntax fails explicitly on 3.10;
this parser never silently drops declarations. No external dependencies.
"""
import ast
import re


def split(text, separator):
    parts, start, quote, escaped, depth = [], 0, None, False, 0
    for i, char in enumerate(text):
        if quote:
            if escaped:
                escaped = False
            elif char == '\\' and quote == '"':
                escaped = True
            elif char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char in '[{':
            depth += 1
        elif char in ']}':
            depth -= 1
        elif char == separator and depth == 0:
            parts.append(text[start:i].strip())
            start = i + 1
    parts.append(text[start:].strip())
    return parts


def value(text):
    text = text.strip()
    if text.startswith(('"""', "'''")):
        raise ValueError('multiline TOML strings require Python 3.11+')
    if text.startswith(('"', "'")):
        result = ast.literal_eval(text)
        if not isinstance(result, str):
            raise ValueError('expected string')
        return result
    if text in ('true', 'false'):
        return text == 'true'
    if text.startswith('[') and text.endswith(']'):
        return [value(x) for x in split(text[1:-1], ',') if x]
    if text.startswith('{') and text.endswith('}'):
        result = {}
        for item in split(text[1:-1], ','):
            if item:
                assign(result, item)
        return result
    if re.fullmatch(r'[+-]?[0-9][0-9_]*', text):
        return int(text.replace('_', ''))
    if re.fullmatch(r'[+-]?[0-9][0-9_]*\.[0-9_]+', text):
        return float(text.replace('_', ''))
    raise ValueError('unsupported TOML value; use Python 3.11+ for full TOML')


def keys(text):
    result = []
    for key in split(text, '.'):
        if re.fullmatch(r'[A-Za-z0-9_-]+', key):
            result.append(key)
        elif key.startswith(('"', "'")):
            result.append(value(key))
        else:
            raise ValueError('unsupported TOML key')
    return result


def descend(node, path):
    for key in path:
        node = node.setdefault(key, {})
        if isinstance(node, list):
            node = node[-1]
        if not isinstance(node, dict):
            raise ValueError('conflicting TOML table')
    return node


def assign(node, text):
    pair = split(text, '=')
    if len(pair) != 2:
        raise ValueError('expected TOML key = value')
    path = keys(pair[0])
    parent = descend(node, path[:-1])
    if path[-1] in parent:
        raise ValueError('duplicate TOML key')
    parent[path[-1]] = value(pair[1])


def comment_free(line):
    quote, escaped = None, False
    for index, char in enumerate(line):
        if quote:
            if escaped:
                escaped = False
            elif char == '\\' and quote == '"':
                escaped = True
            elif char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == '#':
            return line[:index]
    return line


def loads(text):
    root, node, pending = {}, None, ''
    node = root
    seen_tables = set()
    for raw in text.splitlines():
        line = comment_free(raw).strip()
        if not line:
            continue
        if not pending and line.startswith('[') and line.endswith(']'):
            array = line.startswith('[[') and line.endswith(']]')
            path = keys(line[2:-2] if array else line[1:-1])
            if array:
                parent = descend(root, path[:-1])
                rows = parent.setdefault(path[-1], [])
                if not isinstance(rows, list):
                    raise ValueError('conflicting TOML array table')
                rows.append({})
                node = rows[-1]
            else:
                if tuple(path) in seen_tables:
                    raise ValueError('duplicate TOML table')
                seen_tables.add(tuple(path))
                node = descend(root, path)
            continue
        pending += ' ' + line
        # Bracket balance outside strings, using top-level split.
        try:
            assign(node, pending)
        except (ValueError, SyntaxError) as error:
            # Only incomplete arrays/inline tables may continue on a new line.
            rhs = split(pending, '=')
            if len(rhs) == 2 and rhs[1].startswith(('[', '{')) and not rhs[1].endswith((']', '}')):
                continue
            raise ValueError(str(error)) from error
        pending = ''
    if pending:
        raise ValueError('incomplete TOML value')
    return root
