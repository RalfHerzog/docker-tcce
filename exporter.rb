require 'digest'
require 'open-uri'
require 'openssl'
require 'tcce'

require_relative 'exporter_parameters'

# The Exporter handles the workflow to query and export certificates from consul
class Exporter
  # See: https://letsencrypt.org/certificates/
  LE_INTERMEDIATE_URL = 'https://letsencrypt.org/certs/lets-encrypt-r3.pem'.freeze

  # Constructor
  # @param [ExporterParameters] params
  # @return [Exporter] the brand new Exporter object
  def initialize(params)
    raise StandardError, 'Must pass an [ExporterParameters] object as params' unless params.is_a? ExporterParameters

    @logger = Logger.new $stdout
    @logger.level = params.log_level

    @consul = TCCE::Consul.new params.url, params.acl_token,
                               params.kv_path, params.ca_file
    @path = params.path
    @overwrite = params.overwrite
    @bundle = params.bundle
  end

  # Exports the consul object and writes certificates to path
  def export
    raise StandardError, "Export directory [#{@path}] does not exist" unless Dir.exist? @path

    @logger.info 'Begin export procedure. Showtime'

    intermediate_cert = fetch_le_intermediate_cert
    export_le_intermediate_cert intermediate_cert
    kv_content = consul_content
    parse_and_export kv_content, intermediate_cert

    @logger.info 'Finished export procedure'
  end

  private

  # Exports the intermediate certificate
  # @param [OpenSSL::X509::Certificate] intermediate_cert
  def export_le_intermediate_cert(intermediate_cert)
    @logger.debug 'Export intermediate certificate'

    # FIXME: Just an idea to save the original intermediate CA certificate
    # in it's own file. A symlink on that will not be mounted (docker)
    # See: https://stackoverflow.com/a/31885214
    #
    # cn = intermediate_cert.subject.to_a.find { |ary| ary[0] == 'CN' }[1]
    # path = file_path cn, 'crt'
    # write_file path, intermediate_cert.to_s, 0o644

    path = file_path 'intermediate', 'crt'
    safe_write_file path, intermediate_cert.to_s, 0o644

    @logger.debug 'Exported intermediate certificate'
  end

  # Starts parsing key-value store and exports certificates with optional
  # intermediate certificate
  # @param [String] kv_content
  # @param [OpenSSL::X509::Certificate] intermediate_cert
  def parse_and_export(kv_content, intermediate_cert)
    @logger.debug 'Parse the received object'
    tcce_file = TCCE::File.parse kv_content
    tcce_file.certificates do |certificate|
      @logger.info "Export [#{certificate.domain}]"
      write_files certificate, intermediate_cert
    end
  end

  # Downloads the current LE intermediate certificate
  # @return [OpenSSL::Certificate]
  def fetch_le_intermediate_cert
    return nil unless @bundle

    # Fetch intermediate certificate from LetsEncrypt
    OpenSSL::X509::Certificate.new URI.parse(LE_INTERMEDIATE_URL).read
  end

  # Fetches consul kv content
  # @return [String]
  def consul_content
    @logger.info 'Get consul kv object'
    kv_content = @consul.get
    @logger.debug "Received [#{kv_content.length}] bytes"
    kv_content
  end

  # Writes public/private key pair and SAN certificates
  # @param [TCCE::Certificate] certificate
  # @param [OpenSSL::X509::Certificate] intermediate_cert
  def write_files(certificate, intermediate_cert)
    # Single server certificates
    write_certificate certificate
    write_san_files certificate

    # Server bundle certificates
    if intermediate_cert
      write_certificate_bundle certificate, intermediate_cert
      write_san_bundles certificate, intermediate_cert
    end

    write_private_key certificate
  end

  # Writes SAN bundle certificates
  # @param [TCCE::Certificate] certificate
  # @param [OpenSSL::X509::Certificate] intermediate_cert
  def write_san_bundles(certificate, intermediate_cert)
    @logger.debug 'Write SAN bundle certicates'
    (certificate.sans || []).each do |san|
      if certificate.domain == san
        @logger.debug 'Skip because SAN equals domain name'
        next
      end

      write_certificate_bundle certificate, intermediate_cert, san
    end
  end

  # Writes certificate plus intermediate certificate to a 'bundle' file
  # @param [TCCE::Certificate] cert
  # @param [OpenSSL::X509::Certificate] intermediate_cert
  # @param [String] alternative_domain
  def write_certificate_bundle(cert, intermediate_cert, alternative_domain = nil)
    unless cert.certificate.verify intermediate_cert.public_key
      raise StandardError, "Certificate issuer does not match intermediate cert
 serial [#{cert.certificate.serial} != #{intermediate_cert.serial}]"
    end

    path = file_path (alternative_domain || cert.domain), 'bundle.crt'
    @logger.debug "Attempt to write bundle certificate to [#{path}]"

    # Concatenate the server and intermediate certificate
    content = "#{cert.certificate}\n#{intermediate_cert}"
    safe_write_file path, content, 0o644
  end

  # Writes the public certificate content to file
  # @param [TCCE::Certificate] cert
  # @param [String] alternative_domain
  def write_certificate(cert, alternative_domain = nil)
    path = file_path (alternative_domain || cert.domain), 'crt'
    @logger.debug "Attempt to write certificate to [#{path}]"
    safe_write_file path, cert.certificate.to_s, 0o644
  end

  # Writes a file only if it's changed and able to write
  # @param [String] path
  # @param [String] content
  # @param [Fixnum] chmod_mode
  def safe_write_file(path, content, chmod_mode)
    if (content_changed?(path, content) || chmod_changed?(path, chmod_mode)) && (write_ready? path)
      write_file path, content, chmod_mode
    end
  end

  # Return true if file mode for file_path has changed
  # @param [String] file_path
  # @param [Fixnum] chmod_mode
  def chmod_changed?(file_path, chmod_mode)
    return true unless File.exist? file_path

    mode = File.stat(file_path).mode
    !(mode.to_s(8).end_with? chmod_mode.to_s(8))
  end

  # Writes the private key content to file
  # @param [TCCE::Certificate] cert
  def write_private_key(cert)
    path = file_path cert.domain, 'key'
    @logger.debug "Attempt to write private key to [#{path}]"

    safe_write_file path, cert.private_key.to_s, 0o400
  end

  # Creates certificate files for each Subject-Alternative-Name (SAN)
  # @param [TCCE::Certificate] certificate
  def write_san_files(certificate)
    @logger.debug 'Write SAN certificates'
    (certificate.sans || []).each do |san|
      if certificate.domain == san
        @logger.debug 'Skip because SAN equals domain name'
        next
      end

      write_certificate certificate, san
    end
  end

  # Generates a file path for a file to be exported
  # @param [String] filename
  # @param [String] suffix
  # @return [String] file path
  def file_path(filename, suffix)
    file_path = ::File.join @path, "#{filename}.#{suffix}"
    @logger.debug "File export path is [#{file_path}]"
    file_path
  end

  # Checks, if the content of a file has been changed
  # @param [String] file_path
  # @param [String] content
  # @return [Boolean] true if content has changed, false otherwise
  def content_changed?(file_path, content)
    return true unless File.exist? file_path

    content_digest = Digest::SHA256.digest content
    file_digest_hex = Digest::SHA256.file file_path

    if file_digest_hex == Digest.hexencode(content_digest)
      @logger.info "Content of [#{file_path}] did not change. Do not overwrite"
      return false
    end
    true
  end

  # Returns true, if the file_path is ready to be written.
  # If the file exists and ENV['EXPORT_OVERWRITE'] was set, the file gets
  # deleted.
  # @param [String] file_path
  # @return [Boolean] true if file_path is ready to write to
  def write_ready?(file_path)
    if File.exist?(file_path)
      @logger.debug "File [#{file_path}] exists already"
      unless @overwrite
        @logger.warn 'Overwrite NOT allowed. File is not NOT write ready'
        return false
      end
      @logger.info "Delete file [#{file_path}]"

      # TODO: This method should not have any side-effects
      File.delete file_path
    end
    @logger.debug "Path [#{file_path}] is write ready"
    true
  end

  # Writes content to file_path
  # @param [String] file_path
  # @param [String] content
  def write_file(file_path, content, chmod_mode)
    @logger.debug "Create empty file at [#{file_path}]"
    ::File.write file_path, ''
    @logger.debug "Created empty file at [#{file_path}]"

    @logger.debug "Attempt to set permission [#{0o600.to_s(8)}] to [#{file_path}]"
    ::File.chmod 0o600, file_path
    @logger.info "Created empty file at [#{file_path}]"

    @logger.debug "Attempt to write [#{content.length}] bytes to [#{file_path}]"
    ::File.write file_path, content
    @logger.info "Wrote [#{content.length}] bytes to [#{file_path}]"

    @logger.debug "Attempt to set permission [#{chmod_mode.to_s(8)}] to [#{file_path}]"
    ::File.chmod chmod_mode, file_path
    @logger.info "Set permission [#{chmod_mode.to_s(8)}] to [#{file_path}]"
  end
end
