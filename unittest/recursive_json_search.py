from test_data import *
from policy import POLICY

VALID_ROLES = {role for roles in POLICY.values() for role in roles}

def is_allowed(field, role):
    if role not in VALID_ROLES:
        return False
    if field in POLICY:
        return role in POLICY[field]
    return True

def json_search(key, input_object, role=None):
    ret_val = []
    if isinstance(input_object, dict):  # Iterate dictionary
        for k, v in input_object.items():  # searching key in the dict
            if k == key and is_allowed(k, role):
                temp = {k: v}
                ret_val.append(temp)
            if isinstance(v, dict):  # the value is another dict so repeat
                ret_val.extend(json_search(key, v, role))
            elif isinstance(v, list):  # it's a list
                for item in v:
                    if not isinstance(item, (str, int)):  # if dict or list repeat
                        ret_val.extend(json_search(key, item, role))
    else:  # Iterate a list because some APIs return JSON object in a list
        for val in input_object:
            if not isinstance(val, (str, int)):
                ret_val.extend(json_search(key, val, role))
    return ret_val

print(json_search("issueSummary", data, role="viewer"))