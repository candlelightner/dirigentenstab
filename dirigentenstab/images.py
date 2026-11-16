"""Pasted/attached images: one server-side validator and one browser helper shared by chat and terminal."""
import base64

MEDIA_TYPES = {'image/png': 'png', 'image/jpeg': 'jpg', 'image/gif': 'gif', 'image/webp': 'webp'}
ACCEPT = ','.join(MEDIA_TYPES)
MAX_IMAGES = 4
MAX_IMAGE_BYTES = 5 * 1024 * 1024


def sniff(data):
    """Media type from magic bytes, or None."""
    if data.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'image/png'
    if data.startswith(b'\xff\xd8\xff'):
        return 'image/jpeg'
    if data[:6] in (b'GIF87a', b'GIF89a'):
        return 'image/gif'
    if data[:4] == b'RIFF' and data[8:12] == b'WEBP':
        return 'image/webp'


def validate_image(media_type, data):
    """Raise ValueError unless the declared type is allowed and the bytes really are that image (≤ 5 MiB)."""
    if media_type not in MEDIA_TYPES:
        raise ValueError('Images must be PNG, JPEG, GIF or WebP')
    if not isinstance(data, bytes) or not data or len(data) > MAX_IMAGE_BYTES:
        raise ValueError(f'Each image must be 1 byte to {MAX_IMAGE_BYTES // 1024 // 1024} MiB')
    if sniff(data) != media_type:
        raise ValueError('Image content does not match its type')
    return media_type


def validate_images(images):
    images = [(validate_image(media_type, data), data) for media_type, data in images or ()]
    if len(images) > MAX_IMAGES:
        raise ValueError(f'At most {MAX_IMAGES} images per message')
    return images


def data_url(media_type, data):
    return f'data:{media_type};base64,' + base64.b64encode(data).decode()


# Browser side: window.dsImages.add(uploaderId, files) downscales (long edge > 1568 px) and queues files on a hidden ui.upload.
HELPER_JS = """<script>(() => { const LIMIT = 1568, TYPES = %s;
  const wanted = f => TYPES.includes(f.type);
  const encode = (c, type, q) => new Promise(r => c.toBlob(r, type, q));
  async function shrink(file) {
    if (file.type === 'image/gif') return file;
    let bmp; try { bmp = await createImageBitmap(file); } catch (_) { return file; }
    const scale = Math.min(1, LIMIT / Math.max(bmp.width, bmp.height));
    if (scale === 1) { bmp.close(); return file; }
    const c = document.createElement('canvas'); c.width = Math.round(bmp.width * scale); c.height = Math.round(bmp.height * scale);
    const g = c.getContext('2d'); let type = file.type === 'image/png' ? 'image/png' : 'image/jpeg';
    if (type === 'image/jpeg') { g.fillStyle = '#fff'; g.fillRect(0, 0, c.width, c.height); }
    g.drawImage(bmp, 0, 0, c.width, c.height); bmp.close();
    let blob = await encode(c, type, .85);
    if (type === 'image/png' && blob && blob.size > 4 * 1024 * 1024) { type = 'image/jpeg'; blob = await encode(c, type, .85); }
    if (!blob) return file;
    return new File([blob], file.name.replace(/\\.\\w+$/, '') + (type === 'image/png' ? '.png' : '.jpg'), {type});
  }
  const dsImages = window.dsImages = {
    files: list => [...(list || [])].filter(wanted),
    async add(id, files) { const ok = this.files(files); if (!ok.length) return false;
      getElement(id).$refs.qRef.addFiles(await Promise.all(ok.map(shrink))); return true; },
    pick(id) { getElement(id).$refs.qRef.pickFiles(); },
  };
  // Capture-phase paste/drop inside any [data-ds-upload=<uploader id>] box; only events carrying an image file are claimed.
  const take = (e, list) => { const box = e.target.closest?.('[data-ds-upload]');
    if (!box || !dsImages.files(list).length) return;
    e.preventDefault(); e.stopPropagation(); dsImages.add(+box.dataset.dsUpload, list); };
  document.addEventListener('paste', e => take(e, e.clipboardData?.files), true);
  document.addEventListener('dragover', e => { if (e.target.closest?.('[data-ds-upload]') && [...(e.dataTransfer?.types || [])].includes('Files')) e.preventDefault(); }, true);
  document.addEventListener('drop', e => take(e, e.dataTransfer?.files), true);
  })();</script>""" % (list(MEDIA_TYPES),)
