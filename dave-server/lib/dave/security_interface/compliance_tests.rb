# Defined in dave-server/lib/dave/security_interface/compliance_tests.rb
#
# Include this module in a provider spec to verify the implementation satisfies
# the SecurityInterface contract.
#
# Required lets:
#   subject         — the provider instance
#   valid_credentials     — hash { username: "...", password: "..." } for a user with read-write access
#   read_only_credentials — hash { username: "...", password: "..." } for a read-only user
#   invalid_credentials   — hash { username: "...", password: "wrong" } (bad password)
#   read_write_path — path the read-write user can read and write
#   read_only_path  — path the read-only user can read but not write
#   restricted_path — path neither user can access
module Dave
  module SecurityInterface
    module ComplianceTests
      def self.included(base)
        base.describe "SecurityInterface compliance" do
          # --- authenticate ---

          describe "#authenticate" do
            it "returns a Principal when credentials are valid" do
              principal = subject.authenticate(valid_credentials)
              expect(principal).not_to be_nil
              expect(principal).to respond_to(:id)
              expect(principal).to respond_to(:display_name)
            end

            it "returns nil when password is wrong" do
              expect(subject.authenticate(invalid_credentials)).to be_nil
            end

            it "returns nil for unknown username" do
              expect(subject.authenticate(username: "nobody", password: "x")).to be_nil
            end

            it "returned Principal has the correct id" do
              principal = subject.authenticate(valid_credentials)
              expect(principal.id).to eq(valid_credentials[:username])
            end
          end

          # --- challenge ---

          describe "#challenge" do
            it "returns a non-empty string" do
              expect(subject.challenge).to be_a(String)
              expect(subject.challenge).not_to be_empty
            end

            it "contains 'Basic'" do
              expect(subject.challenge).to include("Basic")
            end

            it "contains 'realm='" do
              expect(subject.challenge).to include("realm=")
            end
          end

          # --- authorize ---

          describe "#authorize" do
            context "read-write user on read_write_path" do
              let(:principal) { subject.authenticate(valid_credentials) }

              it "permits :read" do
                expect(subject.authorize(principal, read_write_path, :read)).to be true
              end

              it "permits :write" do
                expect(subject.authorize(principal, read_write_path, :write)).to be true
              end
            end

            context "read-only user on read_only_path" do
              let(:principal) { subject.authenticate(read_only_credentials) }

              it "permits :read" do
                expect(subject.authorize(principal, read_only_path, :read)).to be true
              end

              it "denies :write" do
                expect(subject.authorize(principal, read_only_path, :write)).to be false
              end
            end

            context "restricted path" do
              let(:principal) { subject.authenticate(valid_credentials) }

              it "denies :read on restricted_path" do
                expect(subject.authorize(principal, restricted_path, :read)).to be false
              end

              it "denies :write on restricted_path" do
                expect(subject.authorize(principal, restricted_path, :write)).to be false
              end
            end

            context "nil principal" do
              it "denies :read" do
                expect(subject.authorize(nil, read_write_path, :read)).to be false
              end

              it "denies :write" do
                expect(subject.authorize(nil, read_write_path, :write)).to be false
              end
            end
          end
        end
      end
    end
  end
end
