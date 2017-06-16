# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

# This filter is a domain name parser based on the https://publicsuffix.org/[Public Suffix List]
# for more information on this ruby parser, see https://github.com/weppos/publicsuffix-ruby
#
# by default, parsing "example.s3.amazonaws.com" would yield:
#
# [source,json]
# ----------------------------------
# "tld": {
#   "trd": "example.s3",
#   "domain": "amazonaws.com",
#   "subdomain": "example.s3.amazonaws.com",
#   "sld": "amazonaws",
#   "tld": "com"
# }
# ----------------------------------
#
# setting `private_domains => true` enables private (non-ICANN) domain parsing:
#
# [source,json]
# ----------------------------------
# "tld": {
#   "domain": "example.s3.amazonaws.com",
#   "sld": "example",
#   "tld": "s3.amazonaws.com"
# }
# ----------------------------------
class LogStash::Filters::Tld < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #   example {
  #     message => "My message..."
  #   }
  # }
  #
  config_name "tld"

  # The source field to parse
  config :source, :validate => :string, :default => "message"

  # The target field to place tld fields
  config :target, :validate => :string, :default => "tld"

  # Allows private (non-ICANN) domain parsing
  config :private_domains, :validate => :boolean, :default => false

  public
  def register
    # Add instance variables
    require 'public_suffix'
    PublicSuffix::List.private_domains = @private_domains
  end # def register

  public
  def filter(event)

    if @source and PublicSuffix.valid?(event.get(@source))
      domain = PublicSuffix.parse(event.get(@source))
      # Replace the event message with our message as configured in the
      # config file.
      h = Hash.new
      h['tld'] = domain.tld
      h['sld'] = domain.sld
      h['trd'] = domain.trd
      h['domain'] = domain.domain
      h['subdomain'] = domain.subdomain
      event.set(@target, h)

      # filter_matched should go in the last line of our successful code
      filter_matched(event)

    end
  end # def filter
end # class LogStash::Filters::Example
