"""CloudStack 4.23 administrative domain limits, checked before provisioning."""

MAX_DOMAIN_NAME_CHARS = 255
MAX_DOMAIN_PATH_CHARS = 255


def validate_child(parent_domain: dict, child_name: str) -> None:
    """Validate the actual generated child name; ROOT is level zero.

    CloudStack's domain name/path columns are VARCHAR(255), utf8mb3. Its API
    renders the stored path '/' as 'ROOT' and '/Agents/' as 'ROOT/Agents'.
    """
    if not isinstance(parent_domain, dict):
        raise ValueError('CloudStack parent domain metadata is missing')
    path, level = parent_domain.get('path'), parent_domain.get('level')
    if not isinstance(path, str) or type(level) is not int or level < 0:
        raise ValueError('CloudStack must return a valid parent path and level before subgroup creation')
    parts = path.split('/')
    if parts[0] != 'ROOT' or len(parts) != level + 1:
        raise ValueError('CloudStack parent path and hierarchy level are inconsistent')
    for name in [*parts, child_name]:
        if (not isinstance(name, str) or not name or name in {'.', '..'} or '/' in name
                or not name.isprintable() or any(ord(character) > 0xFFFF for character in name)):
            raise ValueError('CloudStack domain names must be printable UTF-8 BMP text without path separators')
        if len(name) > MAX_DOMAIN_NAME_CHARS:
            raise ValueError(f'CloudStack domain names cannot exceed {MAX_DOMAIN_NAME_CHARS} characters')
    if parent_domain.get('name', parts[-1]) != parts[-1]:
        raise ValueError('CloudStack parent name does not match its returned domain path')
    # Stored paths omit the API's ROOT prefix and include both surrounding slashes.
    stored_child_path = path[len('ROOT'):] + '/' + child_name + '/'
    if len(stored_child_path) > MAX_DOMAIN_PATH_CHARS:
        raise ValueError(f'CloudStack domain path would exceed {MAX_DOMAIN_PATH_CHARS} characters; '
                         'use a shorter subgroup name or a shallower parent')
