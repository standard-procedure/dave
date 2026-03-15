# frozen_string_literal: true

require "spec_helper"
require "samba_dave/protocol/constants"

RSpec.describe SambaDave::Protocol::Constants do
  describe "Command codes" do
    it "defines NEGOTIATE as 0x0000" do
      expect(described_class::Commands::NEGOTIATE).to eq(0x0000)
    end

    it "defines SESSION_SETUP as 0x0001" do
      expect(described_class::Commands::SESSION_SETUP).to eq(0x0001)
    end

    it "defines LOGOFF as 0x0002" do
      expect(described_class::Commands::LOGOFF).to eq(0x0002)
    end

    it "defines TREE_CONNECT as 0x0003" do
      expect(described_class::Commands::TREE_CONNECT).to eq(0x0003)
    end

    it "defines TREE_DISCONNECT as 0x0004" do
      expect(described_class::Commands::TREE_DISCONNECT).to eq(0x0004)
    end

    it "defines CREATE as 0x0005" do
      expect(described_class::Commands::CREATE).to eq(0x0005)
    end

    it "defines CLOSE as 0x0006" do
      expect(described_class::Commands::CLOSE).to eq(0x0006)
    end

    it "defines FLUSH as 0x0007" do
      expect(described_class::Commands::FLUSH).to eq(0x0007)
    end

    it "defines READ as 0x0008" do
      expect(described_class::Commands::READ).to eq(0x0008)
    end

    it "defines WRITE as 0x0009" do
      expect(described_class::Commands::WRITE).to eq(0x0009)
    end

    it "defines LOCK as 0x000A" do
      expect(described_class::Commands::LOCK).to eq(0x000A)
    end

    it "defines IOCTL as 0x000B" do
      expect(described_class::Commands::IOCTL).to eq(0x000B)
    end

    it "defines CANCEL as 0x000C" do
      expect(described_class::Commands::CANCEL).to eq(0x000C)
    end

    it "defines ECHO as 0x000D" do
      expect(described_class::Commands::ECHO).to eq(0x000D)
    end

    it "defines QUERY_DIRECTORY as 0x000E" do
      expect(described_class::Commands::QUERY_DIRECTORY).to eq(0x000E)
    end

    it "defines CHANGE_NOTIFY as 0x000F" do
      expect(described_class::Commands::CHANGE_NOTIFY).to eq(0x000F)
    end

    it "defines QUERY_INFO as 0x0010" do
      expect(described_class::Commands::QUERY_INFO).to eq(0x0010)
    end

    it "defines SET_INFO as 0x0011" do
      expect(described_class::Commands::SET_INFO).to eq(0x0011)
    end

    it "defines OPLOCK_BREAK as 0x0012" do
      expect(described_class::Commands::OPLOCK_BREAK).to eq(0x0012)
    end
  end

  describe "Status codes" do
    it "defines STATUS_SUCCESS as 0x00000000" do
      expect(described_class::Status::SUCCESS).to eq(0x00000000)
    end

    it "defines STATUS_MORE_PROCESSING_REQUIRED as 0xC0000016" do
      expect(described_class::Status::MORE_PROCESSING_REQUIRED).to eq(0xC0000016)
    end

    it "defines STATUS_ACCESS_DENIED as 0xC0000022" do
      expect(described_class::Status::ACCESS_DENIED).to eq(0xC0000022)
    end

    it "defines STATUS_NO_SUCH_FILE as 0xC000000F" do
      expect(described_class::Status::NO_SUCH_FILE).to eq(0xC000000F)
    end

    it "defines STATUS_NOT_IMPLEMENTED as 0xC0000002" do
      expect(described_class::Status::NOT_IMPLEMENTED).to eq(0xC0000002)
    end

    it "defines STATUS_LOGON_FAILURE as 0xC000006D" do
      expect(described_class::Status::LOGON_FAILURE).to eq(0xC000006D)
    end

    it "defines STATUS_BAD_NETWORK_NAME as 0xC00000CC" do
      expect(described_class::Status::BAD_NETWORK_NAME).to eq(0xC00000CC)
    end

    it "defines STATUS_OBJECT_NAME_NOT_FOUND as 0xC0000034" do
      expect(described_class::Status::OBJECT_NAME_NOT_FOUND).to eq(0xC0000034)
    end

    it "defines STATUS_INVALID_PARAMETER as 0xC000000D" do
      expect(described_class::Status::INVALID_PARAMETER).to eq(0xC000000D)
    end
  end

  describe "Header flags" do
    it "defines SERVER_TO_REDIR flag" do
      expect(described_class::Flags::SERVER_TO_REDIR).to eq(0x00000001)
    end

    it "defines ASYNC_COMMAND flag" do
      expect(described_class::Flags::ASYNC_COMMAND).to eq(0x00000002)
    end

    it "defines SIGNED flag" do
      expect(described_class::Flags::SIGNED).to eq(0x00000008)
    end
  end

  describe "Dialects" do
    it "defines SMB 2.0.2 dialect" do
      expect(described_class::Dialects::SMB2_0_2).to eq(0x0202)
    end

    it "defines SMB 2.1 dialect" do
      expect(described_class::Dialects::SMB2_1).to eq(0x0210)
    end

    it "defines SMB 3.0 dialect" do
      expect(described_class::Dialects::SMB3_0).to eq(0x0300)
    end

    it "defines SMB 3.0.2 dialect" do
      expect(described_class::Dialects::SMB3_0_2).to eq(0x0302)
    end

    it "defines SMB 3.1.1 dialect" do
      expect(described_class::Dialects::SMB3_1_1).to eq(0x0311)
    end

    it "defines wildcard dialect for multi-protocol negotiate" do
      expect(described_class::Dialects::WILDCARD).to eq(0x02FF)
    end
  end

  describe "Security mode" do
    it "defines SIGNING_ENABLED" do
      expect(described_class::SecurityMode::SIGNING_ENABLED).to eq(0x0001)
    end

    it "defines SIGNING_REQUIRED" do
      expect(described_class::SecurityMode::SIGNING_REQUIRED).to eq(0x0002)
    end
  end

  describe "Protocol IDs" do
    it "defines the SMB2 protocol ID" do
      expect(described_class::PROTOCOL_ID_SMB2).to eq("\xFESMB".b)
    end

    it "defines the SMB1 protocol ID" do
      expect(described_class::PROTOCOL_ID_SMB1).to eq("\xFFSMB".b)
    end
  end
end
