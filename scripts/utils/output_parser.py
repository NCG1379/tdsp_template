import json
import re

def extract_and_parse_json(text):
    """ Extracts a JSON string from text """
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    match_code_block = re.search(r"```json\s*(\{.*\})\s*```", text, re.DOTALL)
    if match_code_block:
        json_string = match_code_block.group(1)
        try:
            return json.loads(json_string)
        except json.JSONDecodeError:
            pass

    match_unquoted_block = re.search(r"(\{.*\})", text, re.DOTALL)
    if match_unquoted_block:
        json_like_string = match_unquoted_block.group(1)
        quoted_json_string = re.sub(r'([{,]\s*)(\w+)(\s*:)', r'\1"\2"\3', json_like_string)
        try:
            return json.loads(quoted_json_string)
        except json.JSONDecodeError:
            pass

    return {}
