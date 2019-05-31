# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

# This example filter will replace the contents of the default 
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an example.
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

  # The target field to place all the data
  config :target, :validate => :string, :default => "tld"

  public
  def register
    # Add instance variables 
    require 'public_suffix'
  end # def register

  public
  def filter(event)

    if @source and PublicSuffix.valid?(event.get(@source), default_rule: nil)
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
