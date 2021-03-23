require 'logger'
require 'rufus-scheduler'

require_relative 'exporter'

# Fetch environment variables
ca_file = ENV['CA_FILE']
consul_url = ENV.fetch 'CONSUL_URL'
consul_acl_token = ENV.fetch 'CONSUL_ACL_TOKEN'
consul_kv_path = ENV.fetch 'CONSUL_KV_PATH'
cron = ENV.fetch('CRON_PATTERN') { '5 0 * * *' }
export_directory = ENV.fetch 'EXPORT_DIRECTORY'
export_overwrite = ENV['EXPORT_OVERWRITE'] != 'false'
bundle = ENV['BUNDLE_CERTIFICATES'] != 'false'
log_level = ENV.fetch('LOG_LEVEL') { 'DEBUG' }
first_in = ENV.fetch('FIRST_IN', nil)

# Some orchestrators like Kubernetes sometimes do not flush the buffer correctly
$stdout.sync = true

# logging is always good
logger = Logger.new $stdout
logger.level = log_level

logger.info "Wait to run by cron pattern [#{cron}]"
logger.info "but run a single time in [#{first_in}]" if first_in
$stdout.flush

# Make use of Rufus::Scheduler to schedule the certificate export
scheduler = Rufus::Scheduler.new
scheduler.cron cron, first_in: first_in do
  parameters = ExporterParameters.new url: consul_url,
                                      acl_token: consul_acl_token,
                                      kv_path: consul_kv_path,
                                      path: export_directory,
                                      ca_file: ca_file,
                                      overwrite: export_overwrite,
                                      bundle: bundle,
                                      log_level: log_level

  Exporter.new(parameters).export
  logger.info "Wait for next run at cron pattern [#{cron}]"
end
scheduler.join
