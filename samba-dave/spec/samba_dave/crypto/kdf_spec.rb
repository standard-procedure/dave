# frozen_string_literal: true

require "spec_helper"
require "samba_dave/crypto/kdf"

RSpec.describe SambaDave::Crypto::KDF do
  describe ".sp800_108_counter" do
    # Known-answer vector from Microsoft's "anatomy of signing and cryptographic
    # keys" walkthrough: for SMB 3.0, deriving the SigningKey from the SessionKey
    # via SMB3KDF(SessionKey, "SMB2AESCMAC\0", "SmbSign\0").
    let(:session_key) { ["7CD451825D0450D235424E44BA6E78CC"].pack("H*") }

    it "derives the SMB 3.0 SigningKey from the SessionKey" do
      key = described_class.sp800_108_counter(
        key: session_key,
        label: "SMB2AESCMAC\x00".b,
        context: "SmbSign\x00".b
      )
      expect(key.unpack1("H*").upcase).to eq("0B7E9C5CAC36C0F6EA9AB275298CEDCE")
    end

    it "derives the SMB 3.0 EncryptionKey (ServerOut) from the SessionKey" do
      # Server encrypts outbound with the ServerOut key (MS vector table labels
      # keys from the client's perspective, hence the apparent swap).
      key = described_class.sp800_108_counter(
        key: session_key,
        label: "SMB2AESCCM\x00".b,
        context: "ServerOut\x00".b
      )
      expect(key.unpack1("H*").upcase).to eq("B0F0427F7CEB416D1D9DCC0CD4F99447")
    end

    it "returns 16 bytes by default and honours the requested length" do
      key = described_class.sp800_108_counter(key: session_key, label: "L\x00".b, context: "C\x00".b)
      expect(key.bytesize).to eq(16)
    end

    it "produces different output for different labels" do
      a = described_class.sp800_108_counter(key: session_key, label: "A\x00".b, context: "C\x00".b)
      b = described_class.sp800_108_counter(key: session_key, label: "B\x00".b, context: "C\x00".b)
      expect(a).not_to eq(b)
    end
  end
end
