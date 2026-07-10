# frozen_string_literal: true

require "spec_helper"
require "samba_dave/ntlm/session_key"

RSpec.describe SambaDave::NTLM::SessionKey do
  # Known-answer vector taken verbatim from Microsoft's open-specification
  # walkthrough "SMB 2 and SMB 3 security in Windows 10: the anatomy of signing
  # and cryptographic keys" (the NTLMv2 SessionKey calculation example).
  let(:response_key_nt)  { ["AEE3959B44A815F1EB28C9511B4F533B"].pack("H*") }  # NTOWFv2
  let(:nt_proof_str)     { ["63078EB639FE03E20A231C3AE3BF2308"].pack("H*") }
  let(:encrypted_rsk)    { ["3B9BDFF38F5EE8F9663F11A0F4C03A78"].pack("H*") }
  let(:session_base_key) { ["B4CF22566926B1C069ACD80E4D73C814"].pack("H*") }  # == KeyExchangeKey
  let(:exported_key)     { ["270E1BA896585EEB7AF3472D3B4C75A7"].pack("H*") }

  describe ".rc4" do
    it "matches RC4(SessionBaseKey, EncryptedRandomSessionKey) = ExportedSessionKey" do
      expect(described_class.rc4(session_base_key, encrypted_rsk)).to eq(exported_key)
    end

    it "is symmetric (encrypt then decrypt round-trips)" do
      cipher = described_class.rc4("secret-key", "hello world")
      expect(described_class.rc4("secret-key", cipher)).to eq("hello world")
    end
  end

  describe ".derive_exported_session_key" do
    it "returns the SessionBaseKey when key exchange is not negotiated" do
      result = described_class.derive_exported_session_key(
        response_key_nt: response_key_nt,
        nt_proof_str: nt_proof_str,
        encrypted_random_session_key: nil,
        key_exchange: false
      )
      expect(result.unpack1("H*").upcase).to eq("B4CF22566926B1C069ACD80E4D73C814")
    end

    it "RC4-decrypts the EncryptedRandomSessionKey when key exchange is negotiated" do
      result = described_class.derive_exported_session_key(
        response_key_nt: response_key_nt,
        nt_proof_str: nt_proof_str,
        encrypted_random_session_key: encrypted_rsk,
        key_exchange: true
      )
      expect(result.unpack1("H*").upcase).to eq("270E1BA896585EEB7AF3472D3B4C75A7")
    end

    it "ignores a present encrypted key when key exchange is not negotiated" do
      result = described_class.derive_exported_session_key(
        response_key_nt: response_key_nt,
        nt_proof_str: nt_proof_str,
        encrypted_random_session_key: encrypted_rsk,
        key_exchange: false
      )
      expect(result).to eq(session_base_key)
    end
  end
end
