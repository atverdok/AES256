import os
from aiohttp import web
import aiohttp_jinja2
import jinja2
from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto.Protocol.KDF import PBKDF2


SALT = b"$G;Z`!Gl=Yne=,)"


async def encode_file(password, in_filename, filesize, chunksize=64 * 1024):
    kdf = PBKDF2(password, SALT, 64, 1000)
    key = kdf[:32]
    key_mac = kdf[32:]
    mac = HMAC.new(key_mac)
    out_filename = in_filename + '.enc'
    iv = os.urandom(16)
    encryptor = AES.new(key, AES.MODE_CFB, iv)
    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            encrypted = encryptor.encrypt(infile.read())
            mac.update(iv + encrypted)
            outfile.write(mac.hexdigest().encode())
            outfile.write(iv)
            outfile.write(encrypted)
    os.remove(in_filename)
    return out_filename


async def decode_file(password, in_filename, chunksize=64 * 1024):
    kdf = PBKDF2(password, SALT, 64, 1000)
    key = kdf[:32]
    key_mac = kdf[32:]
    mac = HMAC.new(key_mac)
    out_filename = os.path.splitext(in_filename)[0]
    with open(in_filename, 'rb') as infile:
        data = infile.read()
        verify = data[0:32]
        mac.update(data[32:])
        if mac.hexdigest() != verify.decode('utf-8'):
            raise ValueError("Error password")

        iv = data[32:48]
        decryptor = AES.new(key, AES.MODE_CFB, iv)
        decrypted = decryptor.decrypt(data[48:])
        with open(out_filename, 'wb') as outfile:
            outfile.write(decrypted)
    os.remove(in_filename)
    return out_filename


async def get_value(request):
    reader = await request.multipart()

    field = await reader.next()
    assert field.name == 'password'
    password = await field.read(decode=True)

    field = await reader.next()
    assert field.name == 'action'
    action = await field.read(decode=True)

    field = await reader.next()
    assert field.name == 'file'
    filename = field.filename

    return field, password, action, filename


@aiohttp_jinja2.template('download.html')
async def file_handler(request):
    try:
        field, password, action, filename = await get_value(request)
        in_filename = os.path.join(os.path.dirname(__file__), 'files', filename)
        size = 0
        with open(in_filename, 'wb') as f:
            while True:
                chunk = await field.read_chunk()  # 8192 bytes by default.
                if not chunk:
                    break
                size += len(chunk)
                f.write(chunk)

        response_obj = dict()
        if action == b'encode':
            out_filename = await encode_file(password, in_filename, size)
            response_obj['status'] = 'success encode'
        elif action == b'decode':
            out_filename = await decode_file(password, in_filename)
            response_obj['status'] = 'success decode'
        response_obj['download_link'] = request.scheme + '://' + os.path.join(request.host, out_filename)
        return response_obj
    except ValueError:
        return web.json_response({'status': 'error', 'reasone': 'Invalid encryption key'}, content_type='application/json')
    except Exception as e:
        return web.json_response({'status': 'error', 'reasone': str(e)}, content_type='application/json')

@aiohttp_jinja2.template('index.html')
async def index(request):
    return 


app = web.Application()
aiohttp_jinja2.setup(app,
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'template')))

app.router.add_post('/file_handler', file_handler)
app.router.add_get('/', index)
app.router.add_static('/files', 'files')

web.run_app(app, port= os.getenv('PORT', '5050'))
