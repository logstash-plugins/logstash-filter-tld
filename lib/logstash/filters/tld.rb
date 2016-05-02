# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require 'resolv'


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

  # should we parse consider special private domains as TLD
  config :private_domains, :validate => :boolean, :default => true

  # An array of domain fields to be included in the event.
  # Possible fields are: "tld", "sld", "trd", "domain", "subdomain"
  # defaults to domain subdomain
  config :fields, :validate => :array, :default => %w(tld sld trd domain subdomain)

  # Definition File
  config :definition, :validate => :path

  public
  def register
    # Add instance variables
    require 'public_suffix'

    if (@definition.nil?)
        @definition = File.join(File.dirname(__FILE__), "..", "..", "..", "vendor", "public_suffix_list.dat")
    end

    if not File.exists?(@definition)
        raise "You must specify 'definition => ...' in your domains filter (checked file '#{@definition}' which does not exist)"
    end

    PublicSuffix::List.default_definition=(File.new(@definition, "r:utf-8"))
    PublicSuffix::List.private_domains=(@private_domains)
  end # def register

  public
  def filter(event)

    if @source and event[@source]
        input = event[@source]

        # check that the input is not an IP address
        if input =~ Resolv::IPv4::Regex or input =~ Resolv::IPv6::Regex
            return
        end

        if PublicSuffix.valid?(input)
            begin
                publicsuffix = PublicSuffix.parse(input)
            rescue PublicSuffix::DomainNotAllowed
                return
            rescue PublicSuffix::DomainInvalid
                return
            end
            domain = Hash.new
            domain['tld'] = publicsuffix.tld
            domain['sld'] = publicsuffix.sld
            domain['trd'] = publicsuffix.trd
            domain['domain'] = publicsuffix.domain
            domain['subdomain'] = publicsuffix.subdomain

            # Replace the event message with our message as configured in the
            # config file, but only include the configured fields
            event[@target] = Hash.new
            domain.each do |key, value|
                next if value.nil? or (value.is_a?(String) and value.empty?)
                if @fields.nil? or @fields.empty? or @fields.include?(key.to_s)
                    event[@target][key.to_s] = value
                end
            end

            # filter_matched should go in the last line of our successful code
            filter_matched(event)
        end
    end
  end # def filter
end # class LogStash::Filters::Example
