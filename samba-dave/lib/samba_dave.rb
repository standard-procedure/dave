# frozen_string_literal: true

require "samba_dave/protocol/constants"
require "samba_dave/protocol/header"
require "samba_dave/protocol/transport"
require "samba_dave/protocol/commands/negotiate"
require "samba_dave/connection"
require "samba_dave/server"

# SambaDave — SMB2 file server using Dave provider interfaces.
#
# @see SambaDave::Server — the main entry point
module SambaDave
  VERSION = "0.1.0"
end
