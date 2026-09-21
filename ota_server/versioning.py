def version_tuple(v: str):
    return tuple(int(part) for part in v.split("."))


def is_newer(candidate: str, current: str) -> bool:
    return version_tuple(candidate) > version_tuple(current)
