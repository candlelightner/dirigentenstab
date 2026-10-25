import importlib.util
from pathlib import Path
import sqlite3


spec = importlib.util.spec_from_file_location('migration_inventory', Path(__file__).parents[1] / 'scripts/migration_inventory.py')
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


def test_inventory_selects_disk_metadata_and_omits_other_device_configuration():
    result = inventory.device_metadata({
        'workspace': {'type': 'disk', 'pool': 'legacy', 'source': 'workspace', 'path': '/workspace',
                      'secret': 'must not be recorded'},
        'proxy': {'type': 'proxy', 'connect': 'private credentials must not be recorded'},
    })
    assert result == {'workspace': {'type': 'disk', 'pool': 'legacy', 'source': 'workspace', 'path': '/workspace'}}


def test_database_inventory_preserves_data_and_exposes_only_schema_and_counts(tmp_path):
    path = tmp_path / 'legacy.db'
    with sqlite3.connect(path) as conn:
        conn.execute('CREATE TABLE conversations(id INTEGER PRIMARY KEY, text TEXT)')
        conn.execute("INSERT INTO conversations(text) VALUES('private message must not be copied')")
    result = inventory.database_metadata(path)
    assert result['conversations']['rows'] == 1
    assert 'private message' not in str(result)
    with sqlite3.connect(path) as conn:
        assert conn.execute('SELECT text FROM conversations').fetchone()[0] == 'private message must not be copied'
