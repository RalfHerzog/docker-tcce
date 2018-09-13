require 'uri'
require 'virtus'

# Class to provides parameters to Export class
class ExporterParameters
  include Virtus.model(strict: true)

  # @param [URI::HTTPS] url consul API url
  attribute :url, URI::HTTPS
  # @param [String] acl_token consul API acl_token
  attribute :acl_token, String
  # @param [String] kv_path consul key-value storage path to acme object
  attribute :kv_path, String
  # @param [String] path The path to write certificates to
  attribute :path, String
  # @param [String] ca_file Path to ca file for validation
  attribute :ca_file, String, strict: false
  # @param [Boolean] overwrite Overwrite existing certificates?
  attribute :overwrite, Boolean
  # @param [Boolean] bundle Export bundle certificates? (includes intermediate certificate)
  attribute :bundle, Boolean

  # @param [String] log_level Log level from Logger::Severity
  attribute :log_level, String
end