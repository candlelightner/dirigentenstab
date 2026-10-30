"""VM file transfers over the managed SFTP connection: session-bound download grants and upload helper."""
import posixpath
import os
import re
import secrets
import shutil
import stat
import tempfile
import time
from urllib.parse import quote

from fastapi import HTTPException, Request
from fastapi.responses import StreamingResponse

PREFIX = '/vm-files/'
GRANT_SECONDS = 60
MAX_UPLOAD = 100 * 1024 * 1024
CHUNK = 256 * 1024
UPLOAD_LIMIT_TEXT = f'{MAX_UPLOAD // 1024 // 1024} MiB'


def use_spool_dir(path):
    """Spool uploads on disk (the data volume) instead of the small /tmp tmpfs; wipe leftovers from a previous run."""
    shutil.rmtree(path, ignore_errors=True)
    os.makedirs(path, mode=0o700)
    tempfile.tempdir = path


def disposition(path):
    name = re.sub(r'[\x00-\x1f\x7f"\\]', '', posixpath.basename(path)) or 'download'
    return f'attachment; filename="{name.encode("ascii", "replace").decode().replace("?", "_")}"; filename*=UTF-8\'\'{quote(name)}'


async def store_upload(sftp, directory, upload, overwrite=False):
    """Stream one NiceGUI upload into `directory`; the caller asks before overwriting."""
    name = upload.name
    if not name or name in {'.', '..'} or '/' in name or '\0' in name:
        raise ValueError(f'Invalid file name: {name!r}')
    if upload.size() > MAX_UPLOAD:
        raise ValueError(f'{name} exceeds the {UPLOAD_LIMIT_TEXT} upload limit')
    target = posixpath.join(directory, name)
    if not overwrite and await sftp.exists(target):
        raise FileExistsError(name)
    async with sftp.open(target, 'wb') as out:
        async for chunk in upload.iterate(chunk_size=CHUNK):
            await out.write(chunk)


class VMFiles:
    def __init__(self, service):
        self.service = service
        self.grants = {}

    def grant(self, identity, vm_id, path):
        now = time.time()
        self.grants = {key: grant for key, grant in self.grants.items() if grant[3] > now}
        if len(self.grants) >= 256:
            raise ValueError('Too many pending downloads; retry shortly')
        token = secrets.token_urlsafe(32)
        self.grants[token] = (identity['_session'], vm_id, path, now + GRANT_SECONDS)
        return PREFIX + token

    def install(self, app):
        """Install behind the application's existing SessionGuard middleware."""
        @app.get(PREFIX + '{token}')
        async def download(request: Request, token: str):
            identity = request.scope.get('ds_identity', {})
            grant = self.grants.pop(token, None)  # Single use.
            if not grant or grant[3] <= time.time() or identity.get('_session') != grant[0]:
                raise HTTPException(403, 'Download link expired')
            _, vm_id, path, _ = grant
            conn = None
            try:
                conn, _ = await self.service.open_vm_connection(identity, vm_id, 'vm-file-download')
                sftp = await conn.start_sftp_client()
                attrs = await sftp.stat(path)
                if not stat.S_ISREG(attrs.permissions or 0):
                    raise ValueError('Only regular files can be downloaded')
                handle = await sftp.open(path, 'rb')
            except Exception as exc:  # Failed authorization or SFTP error: never leak a 500.
                if conn:
                    conn.close()
                refused = isinstance(exc, (PermissionError, ValueError))
                raise HTTPException(403 if refused else 404, str(exc) if refused else 'File unavailable') from None

            async def stream():
                try:
                    while chunk := await handle.read(CHUNK):
                        yield chunk
                finally:
                    conn.close()

            return StreamingResponse(stream(), media_type='application/octet-stream', headers={
                'content-disposition': disposition(path), **({'content-length': str(attrs.size)} if attrs.size is not None else {})})
