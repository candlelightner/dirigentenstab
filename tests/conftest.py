import os


def pytest_collection_modifyitems(config, items):
    shard = os.environ.get('BROWSER_SHARD')
    if not shard:
        return
    index, count = (int(part) for part in shard.split('/'))
    browser = [item for item in items if item.get_closest_marker('browser')]
    dropped = {id(item) for n, item in enumerate(browser) if n % count != index - 1}
    config.hook.pytest_deselected(items=[item for item in items if id(item) in dropped])
    items[:] = [item for item in items if id(item) not in dropped]
