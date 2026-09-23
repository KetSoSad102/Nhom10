from test_data import *
from policy import POLICY

# SR-4: the only roles "in the policy" are those that appear in POLICY.
VALID_ROLES = frozenset(r for roles in POLICY.values() for r in roles)


def _is_valid_role(role):
    # Exact, case-sensitive match on a str; anything else (None, "Admin",
    # ["admin"], ...) is an unknown role. isinstance first so unhashable
    # roles never reach the set lookup.
    return isinstance(role, str) and role in VALID_ROLES


def _can_read(key, role):
    # SR-1..SR-3: restricted keys need a role from their allow-list.
    # Keys not listed in POLICY are readable by any valid role.
    allowed = POLICY.get(key)
    return allowed is None or role in allowed


def _redact(obj, role):
    # Return a copy of obj with every key the role may not read removed at
    # any depth, so a restricted value cannot leak through a parent key.
    # Building new containers also keeps callers from mutating input data.
    if isinstance(obj, dict):
        return {k: _redact(v, role) for k, v in obj.items() if _can_read(k, role)}
    if isinstance(obj, list):
        return [_redact(v, role) for v in obj]
    return obj


def _search(key, input_object, role):
    ret_val = []
    if isinstance(input_object, dict):
        for k, v in input_object.items():
            if not _can_read(k, role):
                # SR-5: skip the whole restricted subtree, both the match
                # itself and anything nested beneath it.
                continue
            if k == key:
                ret_val.append({k: _redact(v, role)})
            # Recurse into v even when k matched: a matching key's value may
            # itself contain further matches.
            if isinstance(v, (dict, list)):
                ret_val.extend(_search(key, v, role))
    elif isinstance(input_object, list):
        for val in input_object:
            if isinstance(val, (dict, list)):
                ret_val.extend(_search(key, val, role))
    # Scalars (str, int, float, bool, None) cannot contain keys.
    return ret_val


def json_search(key, input_object, role=None):
    # SR-4: no role or a role outside the policy gets no data at all.
    if not _is_valid_role(role):
        return []
    return _search(key, input_object, role)


if __name__ == "__main__":
    print(json_search("issueSummary", data, role="viewer"))
