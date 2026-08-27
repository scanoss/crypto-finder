"""Visit-budget fixture: with/as (sync and async)."""


def encrypt_file(path, key):
    with open(path, "rb") as handle:
        data = handle.read()
    with Cipher(key, mode="GCM") as cipher:
        result = cipher.encrypt(data)
    return result


async def encrypt_file_async(path, key):
    async with open_async(path) as handle:
        data = await handle.read()
    return data
