require 'openssl'
require_relative 'signer/shapes'

module Signer
  DIGESTS = [OpenSSL::Digest::SHA256, OpenSSL::Digest::SHA512].freeze

  def self.digest(data)
    OpenSSL::Digest::SHA256.hexdigest(data)
  end

  class Mac
    def initialize(key)
      @key = key
      @hmac = OpenSSL::HMAC.new(key, "SHA256")
    end

    def sign(data)
      @hmac.update(data)
      @hmac.hexdigest
    end

    def verify(data, tag)
      sign(data) == tag
    end
  end
end
