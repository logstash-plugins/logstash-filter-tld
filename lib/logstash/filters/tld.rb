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
  milestone 1
  
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

    if @source and PublicSuffix.valid?(event[@source])
      domain = PublicSuffix.parse(event[@source])
      # Replace the event message with our message as configured in the
      # config file.
      event[@target] = Hash.new
      event[@target]['tld'] = domain.tld
      event[@target]['sld'] = domain.sld
      event[@target]['trd'] = domain.trd
      event[@target]['domain'] = domain.domain
      event[@target]['subdomain'] = domain.subdomain

      # filter_matched should go in the last line of our successful code
      filter_matched(event)

    end
  end # def filter
end # class LogStash::Filters::Example
