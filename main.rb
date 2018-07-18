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
export_overwrite = ENV['EXPORT_OVERWRITE'] == 'false' ? false : true
log_level = ENV.fetch('LOG_LEVEL') { 'DEBUG' }
first_in = ENV.fetch('FIRST_IN') { nil }

# Some orchestrators like Kubernetes sometimes do not flush the buffer correctly
STDOUT.sync = true

# logging is always good
logger = Logger.new STDOUT
logger.level = log_level

logger.info "Wait to run by cron pattern [#{cron}]"
logger.info "but run a single time in [#{first_in}]" if first_in
STDOUT.flush

# Make use of Rufus::Scheduler to schedule the certificate export
scheduler = Rufus::Scheduler.new
scheduler.cron cron, first_in: first_in do
  exporter = Exporter.new consul_url, consul_acl_token, consul_kv_path,
                          export_directory, ca_file, export_overwrite
  exporter.export
  logger.info "Wait for next run at cron pattern [#{cron}]"
end
scheduler.join
