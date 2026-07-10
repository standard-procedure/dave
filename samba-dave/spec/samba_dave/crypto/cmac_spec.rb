# frozen_string_literal: true

require "spec_helper"
require "samba_dave/crypto/cmac"

RSpec.describe SambaDave::Crypto::CMAC do
  # Known-answer vectors from RFC 4493 (The AES-CMAC Algorithm), §4, using the
  # example key K = 2b7e1516 28aed2a6 abf71588 09cf4f3c.
  let(:key) { ["2b7e151628aed2a6abf7158809cf4f3c"].pack("H*") }
  let(:message) do
    ["6bc1bee22e409f96e93d7e117393172a" \
     "ae2d8a571e03ac9c9eb76fac45af8e51" \
     "30c81c46a35ce411e5fbc1191a0a52ef" \
     "f69f2445df4f9b17ad2b417be66c3710"].pack("H*")
  end

  def hexmac(len)
    described_class.digest(key, message[0, len]).unpack1("H*").upcase
  end

  it "matches the RFC 4493 vector for an empty message" do
    expect(hexmac(0)).to eq("BB1D6929E95937287FA37D129B756746")
  end

  it "matches the RFC 4493 vector for a 16-byte message" do
    expect(hexmac(16)).to eq("070A16B46B4D4144F79BDD9DD04A287C")
  end

  it "matches the RFC 4493 vector for a 40-byte message" do
    expect(hexmac(40)).to eq("DFA66747DE9AE63030CA32611497C827")
  end

  it "matches the RFC 4493 vector for a 64-byte message" do
    expect(hexmac(64)).to eq("51F0BEBF7E3B9D92FC49741779363CFE")
  end

  it "returns a 16-byte binary digest" do
    mac = described_class.digest(key, "hello")
    expect(mac.encoding).to eq(Encoding::BINARY)
    expect(mac.bytesize).to eq(16)
  end
end
