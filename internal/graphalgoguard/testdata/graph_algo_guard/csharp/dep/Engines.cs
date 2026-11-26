using System.Security.Cryptography;

namespace Acme.Crypto.Engines;

public sealed class Sm4Engine
{
    private byte[] key = System.Array.Empty<byte>();

    public void Init(bool forEncryption, byte[] material)
    {
        key = material;
        ExpandKey(forEncryption);
    }

    private void ExpandKey(bool forEncryption)
    {
        using var sha = SHA256.Create();
        key = sha.ComputeHash(key);
    }
}

public static class Digests
{
    public static byte[] Sha256(byte[] data)
    {
        using var sha = SHA256.Create();
        return sha.ComputeHash(data);
    }
}
