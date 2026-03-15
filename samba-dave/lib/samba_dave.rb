# frozen_string_literal: true

require "samba_dave/protocol/constants"
require "samba_dave/protocol/header"
require "samba_dave/protocol/transport"
require "samba_dave/protocol/commands/negotiate"
require "samba_dave/protocol/commands/session_setup"
require "samba_dave/protocol/commands/logoff"
require "samba_dave/protocol/commands/echo"
require "samba_dave/protocol/commands/tree_connect"
require "samba_dave/protocol/commands/create"
require "samba_dave/protocol/commands/close"
require "samba_dave/protocol/commands/query_info"
require "samba_dave/protocol/commands/query_directory"
require "samba_dave/protocol/commands/read"
require "samba_dave/protocol/commands/write"
require "samba_dave/protocol/commands/flush"
require "samba_dave/protocol/commands/cancel"
require "samba_dave/protocol/commands/set_info"
require "samba_dave/ntlm/spnego"
require "samba_dave/ntlm/challenge"
require "samba_dave/security_provider"
require "samba_dave/session"
require "samba_dave/tree_connect"
require "samba_dave/open_file"
require "samba_dave/open_file_table"
require "samba_dave/authenticator"
require "samba_dave/connection"
require "samba_dave/server"

# SambaDave — SMB2 file server using Dave provider interfaces.
#
# @see SambaDave::Server — the main entry point
module SambaDave
  VERSION = "0.1.0"
end
