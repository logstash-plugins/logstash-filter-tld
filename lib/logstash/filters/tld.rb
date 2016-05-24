# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require 'uri'

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

  # private domains
  config :private_domains, :validate => :string, :default => false

  public
  def register
    # Add instance variables 
    require 'public_suffix'

  end # def register

  public
  def filter(event)

    # take the first element in the array, if array is passed

    source_string = event[@source]
    source_string = source_string.first if source_string.is_a?(Array)

    return if source_string.nil? || source_string.empty?

    # private domain config -- default is false which is ideal for most

    PublicSuffix::List.private_domains = @private_domains

    domain = source_string.strip

    # test to see if it's a URL
    begin
      uri = URI(source_string)
      if uri.host
        domain = uri.host
        @logger.info("a url was passed in")
      end
    rescue
      @logger.info("not a url")
    end

    # hostname now ready for parsing
    begin
      domain = PublicSuffix.parse(domain)
      event[@target] = Hash.new
      if domain.tld
        event[@target]['tld'] = domain.tld 
      end
      if domain.sld
        event[@target]['sld'] = domain.sld
      end
      if domain.trd
        event[@target]['trd'] = domain.trd
      end
      if domain.domain
        event[@target]['domain'] = domain.domain
      end
      if domain.subdomain
        event[@target]['subdomain'] = domain.subdomain
      end
      filter_matched(event)
    rescue
      @logger.info("invalid domain")
    end


  end # def filter
end # class LogStash::Filters::Example
