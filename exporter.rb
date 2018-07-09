require 'tcce'

class Exporter
  attr_accessor :consul, :path, :overwrite

  # Constructor
  # @param [String] url consul API url
  # @param [String] acl_token consul API acl_token
  # @param [String] kv_path consul key-value storage path to acme object
  # @param [String] path The path to write certificates to
  # @param [Boolean] overwrite Overwrite existing certificates?
  def initialize(url, acl_token, kv_path, path, ca_file = nil, overwrite = false)
    @logger = Logger.new STDOUT
    @logger.level = ENV.fetch('LOG_LEVEL') { 'DEBUG' }

    self.consul = TCCE::Consul.new url, acl_token, kv_path, ca_file
    self.path = path
    self.overwrite = overwrite

    raise StandardError, "Path [#{path}] does not exist" unless Dir.exist? path
  end

  # Exports the consul object and writes certificates to path
  def export
    @logger.debug 'Get consul kv object'
    kv_content = consul.get
    @logger.debug "Received [#{kv_content.length}] bytes"

    @logger.debug 'Parse the received object'
    tcce_file = TCCE::File.parse kv_content

    tcce_file.certificates do |cert|
      @logger.info "Export [#{cert.domain}]"
      export_certificate cert
    end
  end

  private

  def export_certificate(certificate)
    write_certificate_pair certificate

    # Write SAN-Symlinks
    (certificate.sans || []).each do |san|
      san_path = file_path san, 'crt'

      File.symlink certificate.domain + '.crt', san_path
    end
  end

  def write_certificate_pair(cert)
    cert_path = file_path cert.domain, 'crt'
    key_path = file_path cert.domain, 'key'

    write_file cert_path, cert.certificate.to_s
    write_file key_path, cert.private_key.to_s
  end

  def file_path(filename, suffix)
    file_path = ::File.join path, filename + '.' + suffix

    if File.exist?(file_path) || File.symlink?(file_path)
      @logger.debug "File [#{file_path}] exists already"
      unless overwrite
        raise StandardError, "File [#{file_path}] exists; no overwrite allowed"
      end
      @logger.info "Delete file [#{file_path}]"
      File.delete file_path
    end
    file_path
  end

  def write_file(file_path, content)
    @logger.debug "Write [#{content.length}] bytes to [#{file_path}]"
    ::File.write file_path, content
  end
end