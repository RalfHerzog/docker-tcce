require 'logger'
require 'rufus-scheduler'

require_relative 'exporter'

cron = ENV.fetch('CRON_PATTERN') { '5 0 * * *' }

scheduler = Rufus::Scheduler.new

consul_url = ENV.fetch 'CONSUL_URL'
consul_acl_token = ENV.fetch 'CONSUL_ACL_TOKEN'
consul_kv_path = ENV.fetch 'CONSUL_KV_PATH'
export_directory = ENV.fetch 'EXPORT_DIRECTORY'
ca_file = ENV['CA_FILE']
export_overwrite = ENV['EXPORT_OVERWRITE'] == 'false' ? false : true
log_level = ENV.fetch('LOG_LEVEL') { 'DEBUG' }

STDOUT.sync = true
logger = Logger.new STDOUT
logger.level = log_level

logger.info "Wait to run by cron pattern [#{cron}]"
STDOUT.flush

scheduler.cron cron do
  exporter = Exporter.new consul_url, consul_acl_token, consul_kv_path,
                          export_directory, ca_file, export_overwrite
  exporter.export
end
scheduler.join
