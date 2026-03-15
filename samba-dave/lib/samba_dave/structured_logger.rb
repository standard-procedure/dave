# frozen_string_literal: true

require "logger"

module SambaDave
  # Structured logger for SMB2 server events.
  #
  # Wraps Ruby stdlib Logger and emits structured log lines with context fields:
  # command, session_id, status (NT status code as hex), duration_ms.
  #
  # ## Log levels
  #
  # - INFO  — normal operations: NEGOTIATE, SESSION_SETUP, TREE_CONNECT, CREATE, CLOSE
  # - WARN  — authentication failures (LOGON_FAILURE)
  # - ERROR — unexpected errors with context (session_id, command, status, duration_ms)
  #
  # ## Usage
  #
  #   logger = SambaDave::StructuredLogger.new($stdout)
  #   logger.info("NEGOTIATE", session_id: 0, status: 0, duration_ms: 1)
  #   logger.warn("SESSION_SETUP", session_id: 42, status: 0xC000006D, duration_ms: 3)
  #   logger.error("READ", session_id: 7, status: 0xC0000022, duration_ms: 0)
  #
  # To capture in specs:
  #
  #   io = StringIO.new
  #   logger = SambaDave::StructuredLogger.new(io)
  #
  class StructuredLogger
    # @param output [IO, String] IO object or filename to log to
    def initialize(output = $stdout)
      @logger = Logger.new(output)
      @logger.formatter = method(:format_message)
    end

    # Log at INFO level.
    #
    # @param command [String] SMB2 command name (e.g. "NEGOTIATE")
    # @param session_id [Integer] SMB2 session identifier
    # @param status [Integer] NT status code
    # @param duration_ms [Integer, Float] request processing time in milliseconds
    def info(command, session_id:, status:, duration_ms:, **extra)
      @logger.info(build_message(command, session_id: session_id, status: status,
                                 duration_ms: duration_ms, **extra))
    end

    # Log at WARN level (typically auth failures).
    #
    # @param command [String] SMB2 command name
    # @param session_id [Integer] SMB2 session identifier
    # @param status [Integer] NT status code
    # @param duration_ms [Integer, Float] request processing time in milliseconds
    def warn(command, session_id:, status:, duration_ms:, **extra)
      @logger.warn(build_message(command, session_id: session_id, status: status,
                                 duration_ms: duration_ms, **extra))
    end

    # Log at ERROR level.
    #
    # @param command [String] SMB2 command name
    # @param session_id [Integer] SMB2 session identifier
    # @param status [Integer] NT status code
    # @param duration_ms [Integer, Float] request processing time in milliseconds
    def error(command, session_id:, status:, duration_ms:, **extra)
      @logger.error(build_message(command, session_id: session_id, status: status,
                                  duration_ms: duration_ms, **extra))
    end

    private

    def build_message(command, session_id:, status:, duration_ms:, **extra)
      parts = [
        "cmd=#{command}",
        "session=#{session_id}",
        "status=0x#{status.to_s(16).upcase.rjust(8, '0')}",
        "duration_ms=#{duration_ms}"
      ]
      extra.each { |k, v| parts << "#{k}=#{v}" }
      parts.join(" ")
    end

    def format_message(severity, _datetime, _progname, msg)
      "#{severity} samba-dave #{msg}\n"
    end
  end
end
