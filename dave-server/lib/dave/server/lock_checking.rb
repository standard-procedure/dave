module Dave
  class Server
    # Mixin providing lock-check helpers for write handlers.
    # Requires that the including class exposes @lock_manager and @request.
    module LockChecking
      private

      # Returns true if +path+ is locked and the request does NOT supply
      # a matching token in the If header.
      def locked_without_token?(path)
        return false unless @lock_manager.locked?(path)

        tokens = if_header_tokens
        @lock_manager.locks_for(path).none? { |lock| tokens.include?(lock.token) }
      end

      # Extracts all urn:uuid lock tokens from the HTTP If header.
      def if_header_tokens
        header = @request.env["HTTP_IF"] || ""
        header.scan(/<(urn:uuid:[^>]+)>/).flatten
      end
    end
  end
end
