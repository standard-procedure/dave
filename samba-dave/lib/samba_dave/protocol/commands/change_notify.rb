# frozen_string_literal: true

require "samba_dave/protocol/constants"

module SambaDave
  module Protocol
    module Commands
      # Handles the SMB2 CHANGE_NOTIFY command (MS-SMB2 section 3.3.5.19).
      #
      # Filesystem change notifications are not supported in samba-dave.
      # This stub returns STATUS_NOT_SUPPORTED gracefully without crashing or
      # closing the connection. Clients handle this response by polling instead.
      #
      module ChangeNotify
        # @param body [String] raw request body (ignored)
        # @return [Hash] { status: Integer, body: String }
        def self.handle(body)
          { status: Constants::Status::NOT_SUPPORTED, body: "" }
        end
      end
    end
  end
end
