using Acme.Crypto.Engines;

namespace App;

public sealed class Registry
{
    public void Init(bool forEncryption, byte[] material) { }
}

public static class Service
{
    // A property spelled the way a type is spelled: a using must not make it
    // name one.
    public static Registry Sm4Engine { get; } = new Registry();

    public static void Run(byte[] material)
    {
        // A type the file's using brings in: this call carries the owners the
        // using allows.
        var engine = new Sm4Engine();
        engine.Init(true, material);
        // The property, which carries none.
        Sm4Engine.Init(false, material);
        Digests.Sha256(material);
    }
}
