require 'digest'
require 'open-uri'
require 'openssl'
require 'tcce'

require_relative 'exporter_parameters'

# The Exporter handles the workflow to query and export certificates from consul
class Exporter
  # See: https://letsencrypt.org/certificates/
  LE_INTERMEDIATE_URL = 'https://letsencrypt.org/certs/letsencryptauthorityx3.pem.txt'.freeze

  # Constructor
  # @param [ExporterParameters] params
  # @return [Exporter] the brand new Exporter object
  def initialize(params)
    unless params.is_a? ExporterParameters
      raise StandardError, 'Must pass an [ExporterParameters] object as params'
    end
    @logger = Logger.new STDOUT
    @logger.level = params.log_level

    @consul = TCCE::Consul.new params.url, params.acl_token,
                               params.kv_path, params.ca_file
    @path = params.path
    @overwrite = params.overwrite
    @bundle = params.bundle
  end

  # Exports the consul object and writes certificates to path
  def export
    unless Dir.exist? @path
      raise StandardError, "Export directory [#{@path}] does not exist"
    end

    @logger.info 'Begin export procedure. Showtime'

    intermediate_cert = fetch_le_intermediate_cert
    kv_content = consul_content
    parse_and_export kv_content, intermediate_cert

    @logger.info 'Finished export procedure'
  end

  def parse_and_export(kv_content, intermediate_cert)
    @logger.debug 'Parse the received object'
    tcce_file = TCCE::File.parse kv_content
    tcce_file.certificates do |certificate|
      @logger.info "Export [#{certificate.domain}]"
      write_files certificate, intermediate_cert
    end
  end

  private

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

  # Writes public/private key pair and SAN symlinks
  # @param [TCCE::Certificate] certificate
  # @param [OpenSSL::X509::Certificate] intermediate_cert
  def write_files(certificate, intermediate_cert)
    write_certificate certificate
    write_certificate_bundle certificate, intermediate_cert if intermediate_cert

    create_symlinks certificate

    write_private_key certificate
  end

  # Writes certificate plus intermediate certificate to a 'bundle' file
  # @param [TCCE::Certificate] cert
  # @param [OpenSSL::X509::Certificate] intermediate_cert
  def write_certificate_bundle(cert, intermediate_cert)
    unless cert.certificate.verify intermediate_cert.public_key
      raise StandardError, "Certificate issuer does not match intermediate cert
 serial [#{cert.certificate.serial} != #{intermediate_cert.serial}]"
    end

    path = file_path cert.domain, 'bundle.crt'
    @logger.debug "Attempt to write bundle certificate to [#{path}]"

    content = cert.certificate.to_s + "\n" + intermediate_cert.to_s
    if content_changed? path, content
      write_file path, content, 0o644 if write_ready? path
    end
  end

  # Writes the public certificate content to file
  # @param [TCCE::Certificate] cert
  def write_certificate(cert)
    path = file_path cert.domain, 'crt'
    @logger.debug "Attempt to write certificate to [#{path}]"

    if content_changed? path, cert.certificate.to_s
      write_file path, cert.certificate.to_s, 0o644 if write_ready? path
    end
  end

  # Writes the private key content to file
  # @param [TCCE::Certificate] cert
  def write_private_key(cert)
    path = file_path cert.domain, 'key'
    @logger.debug "Attempt to write private key to [#{path}]"

    if content_changed? path, cert.private_key.to_s
      write_file path, cert.private_key.to_s, 0o400 if write_ready? path
    end
  end

  # Creates symlinks for Subject-Alternative-Names (SAN)
  # @param [TCCE::Certificate] certificate
  def create_symlinks(certificate)
    @logger.debug 'Write SAN symlinks'
    (certificate.sans || []).each do |san|
      if certificate.domain == san
        @logger.debug 'Skip because SAN equals domain name'
        next
      end

      create_certificate_symlink certificate, san
    end
  end

  # Create a symlink for Subject-Alternative-Name (SAN)
  # @param [TCCE::Certificate] certificate
  # @param [String] san ex. san.example.org
  def create_certificate_symlink(certificate, san)
    # Relative link without subdirectory and real path
    san_link = certificate.domain + '.crt'
    san_path = file_path san, 'crt'

    create_symlink san_path, san_link

    # Create bundle link?
    return unless @bundle
    san_link = certificate.domain + '.bundle.crt'
    san_path = file_path san, 'bundle.crt'

    create_symlink san_path, san_link
  end

  def create_symlink(san_path, san_link)
    if File.symlink?(san_path) && File.readlink(san_path) == san_link
      @logger.info 'Skip because symlink (target) did not change'
      return
    end
    return unless write_ready? san_path
    @logger.info "Write [#{san_path}] symlink with link to [#{san_link}]"
    File.symlink san_link, san_path
  end

  # Generates a file path for a file to be exported
  # @param [String] filename
  # @param [String] suffix
  # @return [String] file path
  def file_path(filename, suffix)
    file_path = ::File.join @path, filename + '.' + suffix
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
    if File.exist?(file_path) || File.symlink?(file_path)
      @logger.debug "File [#{file_path}] exists already"
      unless @overwrite
        @logger.warn 'Overwrite NOT allowed. File is not NOT write ready'
        return false
      end
      @logger.info "Delete file [#{file_path}]"
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
    ::File.chmod 0o600, file_path
    @logger.info "Created empty file at [#{file_path}]"

    @logger.debug "Attempt to write [#{content.length}] bytes to [#{file_path}]"
    ::File.write file_path, content
    @logger.info "Wrote [#{content.length}] bytes to [#{file_path}]"

    @logger.debug "Attempt to set permission [#{chmod_mode}] to [#{file_path}]"
    ::File.chmod chmod_mode, file_path
    @logger.info "Set permission [#{chmod_mode}] to [#{file_path}]"
  end
end