require 'signer'
require 'digest'

module App
  def self.run(key, data)
    mac = Signer::Mac.new(key)
    tag = mac.sign(data)
    Digest::SHA256.hexdigest(tag)
  end

  def self.context
    Signer::Context.new.harden
  end
end
