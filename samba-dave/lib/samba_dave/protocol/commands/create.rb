# frozen_string_literal: true

require "bindata"
require "samba_dave/protocol/constants"
require "samba_dave/open_file"

module SambaDave
  module Protocol
    module Commands
      # SMB2 CREATE Request body (MS-SMB2 section 2.2.13) — fixed portion (56 bytes).
      #
      # Offset  Size  Field
      # ──────  ────  ─────
      #  0       2    StructureSize          — always 57 (includes 1 variable byte)
      #  2       1    SecurityFlags          — reserved, must be 0
      #  3       1    RequestedOplockLevel   — 0=NONE, 1=II, 2=EXCLUSIVE, 9=BATCH, 0xFF=LEASE
      #  4       4    ImpersonationLevel     — 0=ANON, 1=IDENT, 2=IMPERSONATE, 3=DELEGATE
      #  8       8    SmbCreateFlags         — reserved
      # 16       8    Reserved               — must be 0
      # 24       4    DesiredAccess          — access mask
      # 28       4    FileAttributes         — file attribute flags
      # 32       4    ShareAccess            — sharing mode
      # 36       4    CreateDisposition      — what to do if file exists / doesn't exist
      # 40       4    CreateOptions          — option flags (DIRECTORY_FILE etc.)
      # 44       2    NameOffset             — offset from start of SMB2 message
      # 46       2    NameLength             — byte length of name (UTF-16LE)
      # 48       4    CreateContextsOffset
      # 52       4    CreateContextsLength
      # 56      var   Buffer                 — name + create contexts
      #
      class CreateRequest < BinData::Record
        endian :little

        uint16 :structure_size
        uint8  :security_flags,           initial_value: 0
        uint8  :requested_oplock_level,   initial_value: 0
        uint32 :impersonation_level,      initial_value: 0
        uint32 :smb_create_flags_high,    initial_value: 0  # two 32-bit halves of SmbCreateFlags
        uint32 :smb_create_flags_low,     initial_value: 0
        uint32 :reserved_high,            initial_value: 0  # two 32-bit halves of Reserved
        uint32 :reserved_low,             initial_value: 0
        uint32 :desired_access,           initial_value: 0
        uint32 :file_attributes,          initial_value: 0
        uint32 :share_access,             initial_value: 0
        uint32 :create_disposition,       initial_value: 0
        uint32 :create_options,           initial_value: 0
        uint16 :name_offset,              initial_value: 0
        uint16 :name_length,              initial_value: 0
        uint32 :create_contexts_offset,   initial_value: 0
        uint32 :create_contexts_length,   initial_value: 0
      end

      # SMB2 CREATE Response body (MS-SMB2 section 2.2.14) — 88 bytes + variable.
      #
      # Offset  Size  Field
      # ──────  ────  ─────
      #  0       2    StructureSize          — always 89 (includes 1 variable byte)
      #  2       1    OplockLevel            — 0=NONE
      #  3       1    Flags                  — 0
      #  4       4    CreateAction           — 0=SUPERSEDED, 1=OPENED, 2=CREATED, 3=OVERWRITTEN
      #  8       8    CreationTime           — FILETIME
      # 16       8    LastAccessTime         — FILETIME
      # 24       8    LastWriteTime          — FILETIME
      # 32       8    ChangeTime             — FILETIME
      # 40       8    AllocationSize         — bytes allocated
      # 48       8    EndOfFile              — actual file size
      # 56       4    FileAttributes         — file attribute flags
      # 60       4    Reserved2              — 0
      # 64       8    FileId.Persistent      — first half of 16-byte FileId
      # 72       8    FileId.Volatile        — second half of 16-byte FileId
      # 80       4    CreateContextsOffset
      # 84       4    CreateContextsLength
      #
      class CreateResponse < BinData::Record
        endian :little

        uint16 :structure_size,          value: 89
        uint8  :oplock_level,            initial_value: 0  # NONE
        uint8  :flags,                   initial_value: 0
        uint32 :create_action,           initial_value: 0
        uint64 :creation_time,           initial_value: 0
        uint64 :last_access_time,        initial_value: 0
        uint64 :last_write_time,         initial_value: 0
        uint64 :change_time,             initial_value: 0
        uint64 :allocation_size,         initial_value: 0
        uint64 :end_of_file,             initial_value: 0
        uint32 :file_attributes,         initial_value: 0
        uint32 :reserved2,               initial_value: 0
        uint64 :file_id_persistent,      initial_value: 0
        uint64 :file_id_volatile,        initial_value: 0
        uint32 :create_contexts_offset,  initial_value: 0
        uint32 :create_contexts_length,  initial_value: 0
      end

      # Handles the SMB2 CREATE command.
      #
      # Opens or creates a file/directory in the filesystem provider, creates an
      # OpenFile handle, and returns the FileId to the client.
      #
      # CreateDisposition:
      #   0 = SUPERSEDE     — replace if exists, create if not
      #   1 = OPEN          — open if exists, fail if not
      #   2 = CREATE        — fail if exists, create if not
      #   3 = OPEN_IF       — open if exists, create if not
      #   4 = OVERWRITE     — overwrite if exists, fail if not
      #   5 = OVERWRITE_IF  — overwrite if exists, create if not
      #
      module Create
        SMB_HEADER_SIZE = 64

        # CreateDisposition constants
        SUPERSEDE    = 0
        OPEN         = 1
        CREATE       = 2
        OPEN_IF      = 3
        OVERWRITE    = 4
        OVERWRITE_IF = 5

        # CreateAction constants (returned in response)
        ACTION_SUPERSEDED  = 0
        ACTION_OPENED      = 1
        ACTION_CREATED     = 2
        ACTION_OVERWRITTEN = 3

        # CreateOptions flags
        FILE_DIRECTORY_FILE     = 0x00000001
        FILE_NON_DIRECTORY_FILE = 0x00000040

        # @param body [String] raw request body (after 64-byte SMB2 header)
        # @param tree_connect [TreeConnect] active tree connect (provides filesystem)
        # @param open_file_table [OpenFileTable] connection-scoped handle table
        # @return [Hash] { status: Integer, body: String }
        def self.handle(body, tree_connect:, open_file_table:)
          request = CreateRequest.read(body)

          # Extract the name from the buffer
          smb_name = extract_name(body, request)
          fs_path  = smb_path_to_fs_path(smb_name)

          filesystem = tree_connect.filesystem

          # Look up the resource
          resource  = filesystem.get_resource(fs_path)
          exists    = !resource.nil?
          is_dir    = exists ? resource.collection? : false

          disposition = request.create_disposition
          options     = request.create_options

          # Validate CreateOptions against actual resource type
          if exists
            if is_dir && (options & FILE_NON_DIRECTORY_FILE) != 0
              return { status: Constants::Status::FILE_IS_A_DIRECTORY, body: "" }
            end
            if !is_dir && (options & FILE_DIRECTORY_FILE) != 0
              return { status: Constants::Status::NOT_A_DIRECTORY, body: "" }
            end
          end

          # Handle by CreateDisposition
          case disposition
          when OPEN
            return { status: Constants::Status::OBJECT_NAME_NOT_FOUND, body: "" } unless exists
            create_open_response(resource, tree_connect, open_file_table, ACTION_OPENED)

          when CREATE
            return { status: Constants::Status::OBJECT_NAME_COLLISION, body: "" } if exists
            resource, err = do_create(filesystem, fs_path, options)
            return err if err
            create_open_response(resource, tree_connect, open_file_table, ACTION_CREATED)

          when OPEN_IF
            if exists
              create_open_response(resource, tree_connect, open_file_table, ACTION_OPENED)
            else
              resource, err = do_create(filesystem, fs_path, options)
              return err if err
              create_open_response(resource, tree_connect, open_file_table, ACTION_CREATED)
            end

          when OVERWRITE, OVERWRITE_IF
            if !exists
              if disposition == OVERWRITE
                return { status: Constants::Status::OBJECT_NAME_NOT_FOUND, body: "" }
              else
                resource, err = do_create(filesystem, fs_path, options)
                return err if err
                return create_open_response(resource, tree_connect, open_file_table, ACTION_CREATED)
              end
            end
            # Overwrite existing: truncate to zero
            begin
              filesystem.write_content(fs_path, StringIO.new(""))
            rescue => e
              return { status: Constants::Status::ACCESS_DENIED, body: "" }
            end
            # Re-read the resource after overwrite
            resource = filesystem.get_resource(fs_path) || resource
            create_open_response(resource, tree_connect, open_file_table, ACTION_OVERWRITTEN)

          when SUPERSEDE
            if exists
              begin
                filesystem.write_content(fs_path, StringIO.new(""))
              rescue => e
                return { status: Constants::Status::ACCESS_DENIED, body: "" }
              end
              resource = filesystem.get_resource(fs_path) || resource
              create_open_response(resource, tree_connect, open_file_table, ACTION_SUPERSEDED)
            else
              resource, err = do_create(filesystem, fs_path, options)
              return err if err
              create_open_response(resource, tree_connect, open_file_table, ACTION_CREATED)
            end

          else
            { status: Constants::Status::INVALID_PARAMETER, body: "" }
          end
        end

        # ── Private helpers ────────────────────────────────────────────────────

        # Extract the filename from the request buffer.
        def self.extract_name(body, request)
          return "" if request.name_length == 0

          buf_start = request.name_offset - SMB_HEADER_SIZE
          return "" if buf_start < 0 || buf_start >= body.bytesize

          name_bytes = body.b[buf_start, request.name_length] || ""
          name_bytes.force_encoding("UTF-16LE").encode("UTF-8", invalid: :replace, undef: :replace)
        end

        # Convert an SMB name (backslash-separated, relative to share root) to
        # a filesystem path (forward-slash-separated, leading "/").
        def self.smb_path_to_fs_path(smb_name)
          return "/" if smb_name.nil? || smb_name.empty? || smb_name == "\\"

          path = smb_name.gsub("\\", "/")
          path = "/" + path unless path.start_with?("/")
          path
        end

        # Create a new file or directory in the filesystem.
        # Returns [resource, nil] on success or [nil, error_result] on failure.
        def self.do_create(filesystem, fs_path, create_options)
          if (create_options & FILE_DIRECTORY_FILE) != 0
            begin
              filesystem.create_collection(fs_path)
              resource = filesystem.get_resource(fs_path + "/") ||
                         filesystem.get_resource(fs_path)
              return [resource, nil]
            rescue => e
              return [nil, { status: Constants::Status::ACCESS_DENIED, body: "" }]
            end
          else
            begin
              filesystem.write_content(fs_path, StringIO.new(""))
              resource = filesystem.get_resource(fs_path)
              return [resource, nil]
            rescue => e
              return [nil, { status: Constants::Status::ACCESS_DENIED, body: "" }]
            end
          end
        end

        # Build the CREATE response and add handle to open_file_table.
        def self.create_open_response(resource, tree_connect, open_file_table, action)
          return { status: Constants::Status::OBJECT_NAME_NOT_FOUND, body: "" } if resource.nil?

          file_id_bytes = open_file_table.generate_file_id
          is_dir        = resource.collection?

          open_file = SambaDave::OpenFile.new(
            file_id_bytes: file_id_bytes,
            path:          resource.path,
            is_directory:  is_dir,
            tree_connect:  tree_connect
          )
          open_file_table.add(open_file)

          attrs = is_dir ? Constants::FileAttributes::DIRECTORY : Constants::FileAttributes::ARCHIVE
          now   = time_to_filetime(resource.last_modified)
          ctime = time_to_filetime(resource.created_at)
          size  = resource.content_length || 0

          # FileId: split 16-byte binary into two uint64 LE values
          persistent = file_id_bytes[0, 8].unpack1("Q<")
          volatile   = file_id_bytes[8, 8].unpack1("Q<")

          response = CreateResponse.new(
            create_action:      action,
            creation_time:      ctime,
            last_access_time:   now,
            last_write_time:    now,
            change_time:        now,
            allocation_size:    (size + 4095) & ~4095,  # round up to 4KB
            end_of_file:        size,
            file_attributes:    attrs,
            file_id_persistent: persistent,
            file_id_volatile:   volatile
          )

          { status: Constants::Status::SUCCESS, body: response.to_binary_s }
        end

        # Convert Ruby Time to Windows FILETIME (100-ns intervals since 1601-01-01).
        def self.time_to_filetime(time)
          return 0 if time.nil?
          (time.to_i * 10_000_000) + (time.nsec / 100) + Constants::FILETIME_EPOCH_DIFF
        end
        private_class_method :extract_name, :smb_path_to_fs_path, :do_create,
                             :create_open_response, :time_to_filetime
      end
    end
  end
end
