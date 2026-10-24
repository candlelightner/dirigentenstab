import pytest

from dirigentenstab.hierarchy import validate_child


SUFFIX = '--ds-' + 'a' * 20


def domain(path, level):
    return {'id': 'trusted-domain-id', 'name': path.split('/')[-1], 'path': path, 'level': level}


def test_real_cloudstack_root_and_child_path_forms():
    validate_child(domain('ROOT', 0), 'Agents' + SUFFIX)
    validate_child(domain('ROOT/Agents' + SUFFIX, 1), 'Research' + SUFFIX)
    validate_child(domain('ROOT/Agents/Research', 2), 'Training' + SUFFIX)
    validate_child(domain('ROOT/ROOT', 1), 'A child of a domain named ROOT' + SUFFIX)


def test_exact_database_path_boundary_counts_slashes_and_omits_api_root_prefix():
    child_name = 'x' + SUFFIX
    parent = domain('ROOT/' + 'P' * 226, 1)
    assert len('/' + 'P' * 226 + '/' + child_name + '/') == 255
    assert len(parent['path'] + '/' + child_name) == 258
    validate_child(parent, child_name)
    with pytest.raises(ValueError, match='path would exceed 255'):
        validate_child(domain('ROOT/' + 'P' * 227, 1), child_name)


def test_generated_suffix_is_included_not_only_display_name():
    parent = domain('ROOT/' + 'P' * 235, 1)
    validate_child(parent, 'Research')
    with pytest.raises(ValueError, match='path would exceed 255'):
        validate_child(parent, 'Research' + SUFFIX)


def test_varchar_limits_are_characters_not_utf8_bytes():
    parent = domain('ROOT/' + '研' * 226, 1)
    child_name = 'x' + SUFFIX
    assert len(('/' + '研' * 226 + '/' + child_name + '/').encode()) > 255
    validate_child(parent, child_name)
    validate_child(domain('ROOT', 0), 'é' * 253)
    with pytest.raises(ValueError, match='path would exceed 255'):
        validate_child(domain('ROOT', 0), 'é' * 254)


def test_maximum_depth_uses_cloudstack_absolute_level_root_zero():
    validate_child(domain('ROOT/' + '/'.join(['a'] * 9), 9), 'child', 10)
    with pytest.raises(ValueError, match='10 levels below ROOT'):
        validate_child(domain('ROOT/' + '/'.join(['a'] * 10), 10), 'child', 10)
    validate_child(domain('ROOT', 0), 'Agents', 1)
    with pytest.raises(ValueError, match='1 levels below ROOT'):
        validate_child(domain('ROOT/Agents', 1), 'Research', 1)
    validate_child(domain('ROOT/' + '/'.join(['a'] * 10), 10), 'child', 11)


@pytest.mark.parametrize('value', [None, False, True, 0, -1, 10.0, '10'])
def test_invalid_depth_configuration_fails_closed(value):
    with pytest.raises(ValueError, match='positive integer'):
        validate_child(domain('ROOT', 0), 'child', value)


@pytest.mark.parametrize('parent', [
    None, [], {}, {'path': None, 'level': 0}, {'path': 'ROOT'},
    {'path': 'ROOT', 'level': True}, {'path': 'ROOT', 'level': '0'},
    {'path': 'ROOT', 'level': -1}, {'path': 'ROOT/Agents', 'level': 0},
    {'path': 'ROOT', 'level': 1}, {'path': '/ROOT/Agents', 'level': 1},
    {'path': 'ROOT/Agents/', 'level': 2}, {'path': 'ROOT//Agents', 'level': 2},
    {'path': 'OTHER/Agents', 'level': 1}, {'path': 'ROOT/../Agents', 'level': 2},
    {'path': 'ROOT/Agents\n', 'level': 1}, {'path': 'ROOT/Agents\0', 'level': 1},
    {'path': 'ROOT/Agents', 'level': 1, 'name': 'Another domain'},
    {'path': 'ROOT/😀', 'level': 1}, {'path': 'ROOT/\ud800', 'level': 1},
])
def test_malformed_or_inconsistent_parent_metadata_fails_closed(parent):
    with pytest.raises(ValueError):
        validate_child(parent, 'child' + SUFFIX)


@pytest.mark.parametrize('name', [None, 7, '', '.', '..', '../ROOT', 'child/name', 'child\n',
                                 'child\0', '😀', '\ud800', 'a' * 256])
def test_invalid_or_unstorable_generated_name_fails_closed(name):
    with pytest.raises(ValueError):
        validate_child(domain('ROOT', 0), name)
