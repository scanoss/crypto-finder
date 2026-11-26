require 'openssl'

module Signer
  class Context
    def initialize
      @ctx = OpenSSL::SSL::SSLContext.new
    end

    def harden
      @ctx.verify_mode = OpenSSL::SSL::VERIFY_PEER
      @ctx
    end
  end

  class Cipher
    def self.build(name: "aes-256-gcm")
      OpenSSL::Cipher.new(name)
    end
  end
end
